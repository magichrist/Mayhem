"""Plan 19 Phase 3 — the fixture certificate authority, the trust decision, and the
X.509 seam that refuses.

What is real here and what is not, asserted rather than asserted-in-prose:

* :class:`FixtureCertificateAuthority` really signs and really verifies. Its
  "signature" is ``HMAC-SHA256`` over the certificate's canonical body and its
  fingerprint is a sha256 over that same body, so a tampered record — a widened
  window, an added role, a swapped fingerprint — is refused by name, and an
  issued certificate satisfies its own ``fingerprint_agrees``.
* **It is not a CA.** ``CA_ALGORITHM_FIXTURE`` (``fixture-ca-hmac-sha256``) is
  stamped on every verdict, every ``TRUSTED`` detail says in its own words that
  this is not a public-key signature and not a chain validation, and there is no
  handshake, session, socket, DER, ASN.1, or RSA anywhere in the module.
* **:class:`X509CertificateAuthority` fails closed**, always, with
  ``SIGNATURE_PORT_UNAVAILABLE``, and never returns a verdict or ``True``. It does
  not fall back to the fixture authority — the downgrade is asserted, because an
  invisible downgrade is exactly how an attacker picks the weaker scheme.
  ``MtlsTrustService.is_real_pkix`` is ``False`` for *both* shipped
  implementations, so a caller cannot report a fixture verdict as a PKI result.
* Phase 1's ``CertificateRef.chain_verified`` is still ``False`` by construction: a
  fixture verdict is not laundered into the recorded certificate.

The conformance matrix is the phase's acceptance — expired, revoked, wrong-role,
unknown-issuer, not-yet-valid, unpinned, forged, and no certificate at all — and
each refusal carries a stable code, so an operator can route on the string rather
than on the wording.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

import pytest

from mayhem.domain.agent_identity import CertificateRef, TrustAnchorRef
from mayhem.domain.errors import DomainError, InvariantViolationError
from mayhem.infra.agent_identity_verifier import (
    ALGORITHM_X509,
    SIGNATURE_PORT_UNAVAILABLE,
    SignaturePortUnavailableError,
)
from mayhem.infra.certificate_authority import (
    CA_ALGORITHM_FIXTURE,
    CONTROLLER_ROLES,
    MTLS_ARTIFACT,
    MTLS_EXPIRED,
    MTLS_NO_CERTIFICATE,
    MTLS_NOT_PINNED,
    MTLS_NOT_YET_VALID,
    MTLS_REVOKED,
    MTLS_UNKNOWN_ISSUER,
    MTLS_WRONG_ROLE,
    TRUST_ORDER,
    CaKeyMaterial,
    FixtureCertificateAuthority,
    IssuedCertificate,
    MtlsRole,
    MtlsTrustRefusedError,
    MtlsTrustService,
    RecordedRevocations,
    TrustReason,
    TrustVerdict,
    X509CertificateAuthority,
    mtls_unavailable_error,
)

if TYPE_CHECKING:
    from collections.abc import Sequence

NOW = datetime(2026, 3, 1, 12, 0, tzinfo=UTC)
CA_ID = "ca-mesh-1"
AGENT_SERIAL = "01"
SECRET = b"c" * 32


def keys() -> CaKeyMaterial:
    return CaKeyMaterial({CA_ID: SECRET})


def authority(material: CaKeyMaterial | None = None) -> FixtureCertificateAuthority:
    return FixtureCertificateAuthority(material if material is not None else keys())


def issue(
    ca: FixtureCertificateAuthority,
    *,
    ca_id: str = CA_ID,
    serial: str = AGENT_SERIAL,
    roles: Sequence[MtlsRole] = (MtlsRole.AGENT,),
    not_before: datetime | None = None,
    not_after: datetime | None = None,
) -> IssuedCertificate:
    return ca.issue(
        ca_id=ca_id,
        subject=f"agent={serial}",
        serial=serial,
        not_before=NOW - timedelta(hours=1) if not_before is None else not_before,
        not_after=NOW + timedelta(hours=1) if not_after is None else not_after,
        roles=list(roles),
    )


def service_for(
    *anchors: TrustAnchorRef, revoked: RecordedRevocations | None = None
) -> MtlsTrustService:
    return MtlsTrustService(authority(), anchors=list(anchors), revoked=revoked)


def raw_certificate(**over: object) -> IssuedCertificate:
    """A hand-built certificate, for the validators that never get to sign."""
    fields: dict[str, object] = {
        "subject": "agent=ag-1",
        "issuer_ca_id": CA_ID,
        "serial": "01",
        "sha256_fingerprint": "0" * 64,
        "not_before": NOW - timedelta(hours=1),
        "not_after": NOW + timedelta(hours=1),
        "roles": (MtlsRole.AGENT,),
        "authority_signature": "A" * 64,
    }
    fields.update(over)
    return IssuedCertificate.model_validate(fields)


# --------------------------------------------------------------------------- #
# The certificate record                                                         #
# --------------------------------------------------------------------------- #


class TestIssuedCertificate:
    def test_an_issued_certificate_agrees_with_its_own_fingerprint(self) -> None:
        """The fingerprint identifies the signed body; it is not part of it.

        A digest taken over a body containing that same digest can never agree
        with it, and a certificate that fails its own fingerprint check cannot
        have an anchor minted for it — so this one assertion is what makes every
        pinning case below reachable at all.
        """
        certificate = issue(authority())
        assert certificate.fingerprint_agrees() is True
        assert certificate.body_digest() == certificate.sha256_fingerprint

    def test_the_signed_body_covers_the_fingerprint_but_the_digest_does_not(self) -> None:
        certificate = issue(authority())
        assert "sha256_fingerprint" not in certificate.core_body()
        assert "sha256_fingerprint" in certificate.body()
        assert "authority_signature" not in certificate.body()

    def test_a_tampered_fingerprint_breaks_the_signature_not_just_the_pin(self) -> None:
        ca = authority()
        certificate = issue(ca)
        forged = raw_certificate(**{**certificate.model_dump(), "sha256_fingerprint": "0" * 64})
        verdict = service_for(ca.anchor(certificate)).authorize(
            forged, required_role=MtlsRole.AGENT, at=NOW
        )
        assert verdict.reason is TrustReason.SIGNATURE_INVALID

    def test_a_certificate_with_no_role_is_refused(self) -> None:
        with pytest.raises(InvariantViolationError) as caught:
            raw_certificate(roles=())
        assert caught.value.rule == "certificate.roles_required"

    def test_an_inverted_window_is_refused(self) -> None:
        with pytest.raises(InvariantViolationError) as caught:
            raw_certificate(
                not_before=NOW + timedelta(hours=1), not_after=NOW, roles=(MtlsRole.AGENT,)
            )
        assert caught.value.rule == "certificate.window"

    def test_a_naive_window_is_refused(self) -> None:
        with pytest.raises(InvariantViolationError) as caught:
            raw_certificate(
                not_before=datetime(2026, 3, 1, 11, 0),  # noqa: DTZ001 - naive on purpose
                roles=(MtlsRole.AGENT,),
            )
        assert caught.value.rule == "certificate.time_aware"

    def test_window_coverage_is_half_open(self) -> None:
        certificate = issue(authority())
        assert certificate.covers(NOW) is True
        assert certificate.covers(certificate.not_after) is False
        assert certificate.covers(certificate.not_before) is True

    def test_the_recorded_ref_still_claims_no_chain_was_validated(self) -> None:
        recorded = issue(authority()).as_recorded_ref()
        assert isinstance(recorded, CertificateRef)
        assert recorded.chain_verified is False
        assert recorded.trust_state == "unverified_plan19_phase1"

    def test_it_describes_itself_with_the_roles_and_the_window(self) -> None:
        rendered = issue(authority()).describe()
        assert "roles [agent]" in rendered
        assert AGENT_SERIAL in rendered


# --------------------------------------------------------------------------- #
# Issuing                                                                        #
# --------------------------------------------------------------------------- #


class TestIssuing:
    def test_an_authority_without_a_key_refuses_to_issue(self) -> None:
        """Minting with an empty secret would produce a certificate every verifier accepts."""
        ca = FixtureCertificateAuthority(CaKeyMaterial({}))
        with pytest.raises(SignaturePortUnavailableError) as caught:
            issue(ca, ca_id="ca-unknown")
        assert caught.value.code == SIGNATURE_PORT_UNAVAILABLE

    def test_a_short_authority_secret_is_refused(self) -> None:
        ca = FixtureCertificateAuthority(CaKeyMaterial({CA_ID: b"short"}))
        with pytest.raises(SignaturePortUnavailableError):
            issue(ca)

    def test_a_non_positive_minimum_is_refused(self) -> None:
        with pytest.raises(DomainError):
            FixtureCertificateAuthority(keys(), minimum_key_bytes=0)

    def test_the_key_map_is_iterable_and_readable(self) -> None:
        material = keys()
        material.add("ca-2", b"d" * 32)
        assert list(material) == ["ca-2", CA_ID]  # sorted, so the listing is reproducible
        assert material.lookup("nothing") is None

    def test_an_anchor_cannot_be_minted_for_a_tampered_certificate(self) -> None:
        ca = authority()
        certificate = issue(ca)
        broken = raw_certificate(**{**certificate.model_dump(), "sha256_fingerprint": "1" * 64})
        with pytest.raises(InvariantViolationError) as caught:
            ca.anchor(broken)
        assert caught.value.rule == "certificate.fingerprint_disagrees"

    def test_the_anchor_names_the_issuer_so_phase_one_pinning_accepts_it(self) -> None:
        """Phase 1 compares ``anchor.subject`` with the certificate's ``issuer``.

        An anchor naming the leaf subject instead reads as
        ``PinReason.ISSUER_MISMATCH``, and before the pinning verdict reached the
        refusal path that mismatch was printed inside a ``TRUSTED`` verdict.
        """
        ca = authority()
        certificate = issue(ca)
        anchor = ca.anchor(certificate)
        assert anchor.ca_id == CA_ID
        assert anchor.subject == certificate.issuer_ca_id


# --------------------------------------------------------------------------- #
# The conformance matrix                                                         #
# --------------------------------------------------------------------------- #


class TestTheTrustDecision:
    def test_a_valid_pinned_certificate_is_trusted(self) -> None:
        ca = authority()
        certificate = issue(ca)
        verdict = service_for(ca.anchor(certificate)).authorize(
            certificate, required_role=MtlsRole.AGENT, at=NOW
        )
        assert verdict.trusted is True
        assert verdict.reason is TrustReason.TRUSTED
        assert verdict.algorithm == CA_ALGORITHM_FIXTURE
        assert verdict.certificate_serial == AGENT_SERIAL
        assert verdict.refusal_code == ""
        # The passing detail says out loud what the check did and was not.
        assert "NOT a public-key signature" in verdict.detail
        assert "NOT an X.509 chain validation" in verdict.detail

    def test_no_certificate_offered_fails_closed(self) -> None:
        verdict = service_for().authorize(None, required_role=MtlsRole.AGENT, at=NOW)
        assert verdict.reason is TrustReason.NO_CERTIFICATE
        assert verdict.refusal_code == MTLS_NO_CERTIFICATE
        assert verdict.certificate_serial == ""
        assert verdict.roles == ()

    def test_an_expired_certificate_is_refused(self) -> None:
        ca = authority()
        certificate = issue(
            ca, not_before=NOW - timedelta(hours=3), not_after=NOW - timedelta(hours=2)
        )
        verdict = service_for(ca.anchor(certificate)).authorize(
            certificate, required_role=MtlsRole.AGENT, at=NOW
        )
        assert verdict.reason is TrustReason.EXPIRED
        assert verdict.refusal_code == MTLS_EXPIRED
        assert "had already closed" in verdict.detail

    def test_a_not_yet_valid_certificate_is_refused(self) -> None:
        ca = authority()
        certificate = issue(
            ca, not_before=NOW + timedelta(hours=1), not_after=NOW + timedelta(hours=2)
        )
        verdict = service_for(ca.anchor(certificate)).authorize(
            certificate, required_role=MtlsRole.AGENT, at=NOW
        )
        assert verdict.reason is TrustReason.NOT_YET_VALID
        assert verdict.refusal_code == MTLS_NOT_YET_VALID
        assert "not open yet" in verdict.detail

    def test_a_revoked_certificate_is_refused(self) -> None:
        ca = authority()
        certificate = issue(ca)
        verdict = service_for(
            ca.anchor(certificate), revoked=RecordedRevocations([AGENT_SERIAL])
        ).authorize(certificate, required_role=MtlsRole.AGENT, at=NOW)
        assert verdict.reason is TrustReason.REVOKED
        assert verdict.refusal_code == MTLS_REVOKED

    def test_a_certificate_from_an_unconfigured_issuer_is_refused(self) -> None:
        ca = authority()
        certificate = issue(ca)
        verdict = service_for().authorize(certificate, required_role=MtlsRole.AGENT, at=NOW)
        assert verdict.reason is TrustReason.UNKNOWN_ISSUER
        assert verdict.refusal_code == MTLS_UNKNOWN_ISSUER
        assert "0 anchor(s)" in verdict.detail

    def test_an_issuer_whose_key_the_verifier_lost_is_refused_not_accepted(self) -> None:
        """An absent key must never become an empty secret that makes the check vacuous."""
        ca = authority()
        certificate = issue(ca)
        anchor = ca.anchor(certificate)
        service = MtlsTrustService(FixtureCertificateAuthority(CaKeyMaterial({})), anchors=[anchor])

        verdict = service.authorize(certificate, required_role=MtlsRole.AGENT, at=NOW)

        assert verdict.reason is TrustReason.SIGNATURE_INVALID
        assert "could not be checked at all" in verdict.detail
        # The same certificate is trusted by a service that still holds the key.
        assert (
            service_for(anchor).authorize(certificate, required_role=MtlsRole.AGENT, at=NOW).trusted
            is True
        )

    def test_a_widened_window_is_refused_as_a_forgery(self) -> None:
        ca = authority()
        certificate = issue(ca)
        forged = raw_certificate(
            **{**certificate.model_dump(), "not_after": (NOW + timedelta(days=365)).isoformat()}
        )
        verdict = service_for(ca.anchor(certificate)).authorize(
            forged, required_role=MtlsRole.AGENT, at=NOW
        )
        assert verdict.reason is TrustReason.SIGNATURE_INVALID

    def test_an_added_role_is_refused_as_a_forgery(self) -> None:
        """A forged record must not be able to *grant itself* the controller role."""
        ca = authority()
        certificate = issue(ca)
        forged = raw_certificate(
            **{**certificate.model_dump(), "roles": (MtlsRole.AGENT, MtlsRole.CONTROLLER)}
        )
        verdict = service_for(ca.anchor(certificate)).authorize(
            forged, required_role=MtlsRole.CONTROLLER, at=NOW
        )
        assert verdict.reason is TrustReason.SIGNATURE_INVALID

    def test_a_certificate_from_another_authority_is_refused(self) -> None:
        ours = authority()
        theirs = FixtureCertificateAuthority(CaKeyMaterial({"ca-other": b"e" * 32}))
        foreign = issue(theirs, ca_id="ca-other", serial="99")

        verdict = service_for(ours.anchor(issue(ours))).authorize(
            foreign, required_role=MtlsRole.AGENT, at=NOW
        )

        assert verdict.reason is TrustReason.UNKNOWN_ISSUER

    def test_a_certificate_with_the_wrong_role_is_refused(self) -> None:
        ca = authority()
        certificate = issue(ca, roles=(MtlsRole.AGENT,))
        verdict = service_for(ca.anchor(certificate)).authorize(
            certificate, required_role=MtlsRole.CONTROLLER, at=NOW
        )
        assert verdict.reason is TrustReason.WRONG_ROLE
        assert verdict.refusal_code == MTLS_WRONG_ROLE

    def test_a_certificate_nobody_pinned_is_refused(self) -> None:
        """**The negative control the phase's acceptance names.**

        Before the pinning verdict was wired into the refusal path this case
        returned ``TRUSTED`` while its own detail said "not pinned" — an unpinned
        certificate being trusted, printed with the words that said otherwise.
        """
        ca = authority()
        pinned = issue(ca)
        unpinned = issue(ca, serial="02")

        verdict = MtlsTrustService(ca, anchors=[ca.anchor(pinned)]).authorize(
            unpinned, required_role=MtlsRole.AGENT, at=NOW
        )

        assert verdict.reason is TrustReason.NOT_PINNED
        assert verdict.refusal_code == MTLS_NOT_PINNED
        assert "trusts what it did not pin" in verdict.detail

    def test_an_anchor_that_names_a_different_issuer_is_not_a_pin(self) -> None:
        ca = authority()
        certificate = issue(ca)
        mismatched = TrustAnchorRef(
            ca_id=CA_ID,
            subject="ca-somebody-else",
            sha256_fingerprint=certificate.sha256_fingerprint,
        )

        verdict = MtlsTrustService(ca, anchors=[mismatched]).authorize(
            certificate, required_role=MtlsRole.AGENT, at=NOW
        )

        assert verdict.reason is TrustReason.NOT_PINNED
        assert verdict.refusal_code == MTLS_NOT_PINNED

    def test_a_naive_check_instant_is_refused(self) -> None:
        ca = authority()
        certificate = issue(ca)
        with pytest.raises(InvariantViolationError) as caught:
            service_for(ca.anchor(certificate)).authorize(
                certificate,
                required_role=MtlsRole.AGENT,
                at=datetime(2026, 3, 1, 12, 0),  # noqa: DTZ001 - naive on purpose
            )
        assert caught.value.rule == "mtls.time_aware"


class TestVerdictShape:
    def test_trusted_is_an_identity_test_not_a_boolean(self) -> None:
        assert TrustVerdict(reason=TrustReason.TRUSTED, detail="d").trusted is True
        assert TrustVerdict(reason=TrustReason.EXPIRED, detail="d").trusted is False

    def test_the_declared_order_is_the_canonical_order(self) -> None:
        assert tuple(TrustReason) == TRUST_ORDER
        assert TrustReason.TRUSTED is TRUST_ORDER[0]

    def test_every_refusal_has_a_stable_code_and_the_artifact_label_is_published(self) -> None:
        for reason in TRUST_ORDER:
            if reason is TrustReason.TRUSTED:
                continue
            assert TrustVerdict(reason=reason, detail="d").refusal_code.startswith("mtls_")
        assert MTLS_ARTIFACT == "agent_certificate"

    def test_require_trusted_raises_with_this_verdicts_code(self) -> None:
        verdict = TrustVerdict(reason=TrustReason.REVOKED, detail="d")
        with pytest.raises(MtlsTrustRefusedError) as caught:
            verdict.require_trusted()
        assert caught.value.code == MTLS_REVOKED
        assert caught.value.verdict is verdict
        assert "pinned in the configured anchors" in caught.value.remediation
        assert TrustVerdict(reason=TrustReason.TRUSTED, detail="d").require_trusted() is not None

    def test_the_description_marks_the_algorithm_and_the_serial(self) -> None:
        rendered = TrustVerdict(
            reason=TrustReason.TRUSTED,
            detail="d",
            algorithm=CA_ALGORITHM_FIXTURE,
            certificate_serial="01",
        ).describe()
        assert "trusted" in rendered
        assert CA_ALGORITHM_FIXTURE in rendered
        assert "[01]" in rendered


# --------------------------------------------------------------------------- #
# The service, and the roles                                                      #
# --------------------------------------------------------------------------- #


class TestMtlsTrustService:
    def test_it_is_never_backed_by_a_real_pkix(self) -> None:
        ca = authority()
        assert service_for(ca.anchor(issue(ca))).is_real_pkix is False
        assert MtlsTrustService(X509CertificateAuthority()).is_real_pkix is False

    def test_the_anchor_set_is_a_constructor_argument(self) -> None:
        ca = authority()
        pinned = service_for(ca.anchor(issue(ca)))
        assert len(pinned.anchors) == 1
        assert pinned.with_anchors([]).anchors == ()
        assert pinned.algorithm == CA_ALGORITHM_FIXTURE

    def test_the_controller_check_accepts_both_controller_roles(self) -> None:
        assert frozenset({MtlsRole.CONTROLLER, MtlsRole.STANDBY_CONTROLLER}) == CONTROLLER_ROLES
        ca = authority()
        for role in (MtlsRole.CONTROLLER, MtlsRole.STANDBY_CONTROLLER):
            certificate = issue(ca, serial=f"c-{role.value}", roles=(role,))
            verdict = service_for(ca.anchor(certificate)).controller_capable(certificate, at=NOW)
            assert verdict.trusted is True

    def test_an_agent_certificate_cannot_present_as_the_controller(self) -> None:
        ca = authority()
        certificate = issue(ca, roles=(MtlsRole.AGENT,))

        verdict = service_for(ca.anchor(certificate)).controller_capable(certificate, at=NOW)

        assert verdict.trusted is False
        assert verdict.refusal_code == MTLS_WRONG_ROLE

    def test_a_standby_certificate_is_refused_on_the_live_controller_link(self) -> None:
        """The asymmetry is the point of recording the distinction."""
        ca = authority()
        certificate = issue(ca, roles=(MtlsRole.STANDBY_CONTROLLER,))
        service = service_for(ca.anchor(certificate))
        assert service.controller_capable(certificate, at=NOW).trusted is True
        on_controller_link = service.authorize(
            certificate, required_role=MtlsRole.CONTROLLER, at=NOW
        )
        assert on_controller_link.trusted is False

    def test_an_auditor_certificate_cannot_authorise_anything(self) -> None:
        ca = authority()
        certificate = issue(ca, roles=(MtlsRole.AUDITOR,))
        assert (
            service_for(ca.anchor(certificate)).controller_capable(certificate, at=NOW).trusted
            is False
        )

    def test_authorize_or_raise_raises_on_a_refusal(self) -> None:
        ca = authority()
        certificate = issue(ca)
        service = service_for(ca.anchor(certificate))
        with pytest.raises(MtlsTrustRefusedError):
            service.authorize_or_raise(certificate, required_role=MtlsRole.CONTROLLER, at=NOW)
        assert (
            service.authorize_or_raise(certificate, required_role=MtlsRole.AGENT, at=NOW).trusted
            is True
        )

    def test_the_revocation_source_defaults_to_an_empty_set(self) -> None:
        ca = authority()
        certificate = issue(ca)
        assert (
            MtlsTrustService(ca, anchors=[ca.anchor(certificate)])
            .authorize(certificate, required_role=MtlsRole.AGENT, at=NOW)
            .trusted
            is True
        )


# --------------------------------------------------------------------------- #
# The X.509 seam: defined, and refused                                           #
# --------------------------------------------------------------------------- #


class TestTheX509SeamFailsClosed:
    def test_it_refuses_with_the_one_code_the_plan_uses_everywhere(self) -> None:
        ca = authority()
        certificate = issue(ca)
        with pytest.raises(SignaturePortUnavailableError) as caught:
            X509CertificateAuthority().verify_certificate(
                certificate,
                anchors=[ca.anchor(certificate)],
                required_role=MtlsRole.AGENT,
                revoked=RecordedRevocations(),
                at=NOW,
            )
        assert caught.value.code == SIGNATURE_PORT_UNAVAILABLE
        assert caught.value.algorithm == ALGORITHM_X509

    def test_it_raises_even_for_an_input_it_could_trivially_accept(self) -> None:
        """No verdict path exists, so no input can produce one."""
        with pytest.raises(SignaturePortUnavailableError):
            X509CertificateAuthority().verify_certificate(
                None,
                anchors=[],
                required_role=MtlsRole.AUDITOR,
                revoked=RecordedRevocations(),
                at=NOW,
            )

    def test_it_does_not_fall_back_to_the_fixture_authority(self) -> None:
        """The downgrade is the attack: a caller must not be silently given HMAC."""
        ca = authority()
        certificate = issue(ca)
        service = MtlsTrustService(X509CertificateAuthority(), anchors=[ca.anchor(certificate)])
        with pytest.raises(SignaturePortUnavailableError):
            service.authorize(certificate, required_role=MtlsRole.AGENT, at=NOW)
        with pytest.raises(SignaturePortUnavailableError):
            service.authorize_or_raise(certificate, required_role=MtlsRole.AGENT, at=NOW)

    def test_an_unavailable_port_is_not_a_refused_certificate(self) -> None:
        """Nothing was checked is a different fact from checked and wrong."""
        with pytest.raises(SignaturePortUnavailableError):
            MtlsTrustService(X509CertificateAuthority()).authorize(
                None, required_role=MtlsRole.AGENT, at=NOW
            )

    def test_the_refusal_is_available_as_a_value(self) -> None:
        error = mtls_unavailable_error()
        assert error.code == SIGNATURE_PORT_UNAVAILABLE
        assert "no third-party dependency" in error.reason
        assert "refuses rather than verifying with something weaker" in error.reason
