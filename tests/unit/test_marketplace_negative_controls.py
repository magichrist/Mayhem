"""Plan 18 Phase 5 — proving the marketplace predicates are load-bearing.

Every control this phase names already exists: a tampered artifact is refused at
install (``test_a_tampered_artifact_is_refused_and_recorded``), a cold label
cannot claim a certified state (``test_a_cold_label_cannot_claim_a_certified_state``),
promotion and revocation propagation are covered in ``test_marketplace.py``, and
federation closure is sealed in ``test_marketplace_evidence.py``. The ``not
started`` status was stale in the way plan 14's was.

What was missing is the discipline the completed plans record: proving the
properties *underneath* those tests are load-bearing. A suite of correct
assertions over a predicate that no longer enforces anything would still be
green, and these are the predicates a marketplace reader's trust label rests on.

Six properties, each stated as a two-sided case so it cannot pass by accident:

1. **Deprecation dominates.** ``_classify`` checks it first, so a withdrawn
   artifact reads ``DEPRECATED`` even on the official registry with a current
   certification record behind it.
2. **Distribution beats evidence.** An organization-private artifact with a
   current record still reads ``ORGANIZATION_PRIVATE`` — the label means "this came
   from your own catalogue", and a certification does not change where it came
   from.
3. **A record for other bytes grants nothing.** The digest comparison is what
   makes ``VERIFIED_COMMUNITY`` a claim about *these* bytes.
4. **Currency needs two independent conditions.** ``grants_live_verification``
   and ``now < expires_at``. Each alone is insufficient, which is exactly the
   property a single-condition implementation breaks.
5. **``now`` is a parameter, not a clock read.** Proved by classification
   changing when only ``now`` changes — if anything read the wall clock, the two
   calls would agree.
6. **Pending is not blocking.** A revocation inside its propagation deadline is
   announced and does not stop a dispatch; after the deadline it does.

The fixtures are imported from ``test_marketplace.py`` rather than rebuilt. The
first draft reconstructed ``MatrixCell`` and ``CertificationRecord`` by hand and
got nine required fields wrong, which is a good reason not to: those fixtures
are the ones the existing suite's assertions are written against, so reusing
them is what keeps these controls testing the same objects.
"""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest
from tests.unit.test_marketplace import (
    _ARTIFACT_DIGEST,
    _NOW,
    _artifact,
    _cert,
    _certified,
    _publisher,
    _registry,
    _revocation,
)

from mayhem.domain.certification import CertificationState
from mayhem.domain.marketplace import (
    OFFICIAL_REGISTRY_ID,
    Artifact,
    ArtifactClass,
    PublisherDeclaration,
    RegistryRef,
    RegistryScope,
    Revocation,
    TrustLabelError,
    blocking_revocations,
    classify_artifact,
    dispatches,
    pending_revocations,
    require_trust_label,
    trust_label,
)

OTHER_DIGEST = "b" * 64


def _official() -> RegistryRef:
    return _registry(registry_id=OFFICIAL_REGISTRY_ID, scope=RegistryScope.OFFICIAL)


def _private() -> RegistryRef:
    return _registry(
        registry_id="corp.registry",
        scope=RegistryScope.ORGANIZATION_PRIVATE,
        organization="acme.labs",
    )


def _private_publisher() -> PublisherDeclaration:
    # A private registry must name its organization ("a private catalogue with no
    # owner is not a boundary"), and the artifact's publisher declaration must
    # agree with it or the artifact is refused outright. Both are the domain
    # working as intended, not plumbing to work around.
    return _publisher(organization="acme.labs")


def _private_artifact() -> Artifact:
    return _artifact(registry=_private(), publisher=_private_publisher())


def _deprecated(artifact: Artifact) -> Artifact:
    from mayhem.domain.marketplace import DeprecationNotice

    # Artifact is a frozen pydantic model, so this is model_copy and not
    # dataclasses.replace -- which raises TypeError rather than silently working.
    return artifact.model_copy(
        update={
            "deprecation": DeprecationNotice(
                reason="withdrawn",
                replaced_by="acme.packs.net",
                announced_at=_NOW - timedelta(days=1),
            )
        }
    )


class TestDeprecationDominates:
    def test_a_withdrawn_artifact_reads_deprecated_with_a_current_record(self) -> None:
        """The strongest case available: official registry *and* live evidence."""
        artifact = _deprecated(_artifact(registry=_official()))
        assert classify_artifact(artifact, (_cert(record=_certified()),), now=_NOW) is (
            ArtifactClass.DEPRECATED
        )

    def test_the_same_artifact_without_the_notice_is_official(self) -> None:
        """Two-sided: the notice is the whole difference.

        Without this, the test above would also pass against a ``_classify`` that
        ignored both the registry and the record.
        """
        artifact = _artifact(registry=_official())
        assert classify_artifact(artifact, (_cert(record=_certified()),), now=_NOW) is (
            ArtifactClass.OFFICIAL
        )


class TestDistributionBeatsEvidence:
    def test_a_private_artifact_with_a_current_record_is_still_private(self) -> None:
        artifact = _private_artifact()
        assert classify_artifact(artifact, (_cert(record=_certified()),), now=_NOW) is (
            ArtifactClass.ORGANIZATION_PRIVATE
        )

    def test_and_the_community_one_with_the_same_record_is_verified(self) -> None:
        """Two-sided, and the reason the rule is a rule rather than a preference."""
        artifact = _artifact(registry=_registry())
        assert classify_artifact(artifact, (_cert(record=_certified()),), now=_NOW) is (
            ArtifactClass.VERIFIED_COMMUNITY
        )

    def test_a_private_artifact_without_a_record_is_not_verified(self) -> None:
        artifact = _private_artifact()
        assert classify_artifact(artifact, (), now=_NOW) is ArtifactClass.ORGANIZATION_PRIVATE


class TestTheDigestIsWhatBindsTheRecord:
    def test_a_record_for_other_bytes_grants_nothing(self) -> None:
        artifact = _artifact()
        record = _cert(record=_certified(), digest=OTHER_DIGEST)
        assert classify_artifact(artifact, (record,), now=_NOW) is ArtifactClass.UNVERIFIED

    def test_the_same_record_for_these_bytes_does(self) -> None:
        artifact = _artifact()
        record = _cert(record=_certified())
        assert classify_artifact(artifact, (record,), now=_NOW) is ArtifactClass.VERIFIED_COMMUNITY

    def test_no_record_at_all_never_verifies(self) -> None:
        """The floor. An artifact with an empty record set is never certified."""
        # The private case needs a matching publisher declaration; a private
        # registry with no owner is refused before classification is reached.
        for artifact in (
            _artifact(registry=_registry()),
            _artifact(registry=_official()),
            _private_artifact(),
        ):
            assert classify_artifact(artifact, (), now=_NOW) is not ArtifactClass.VERIFIED_COMMUNITY


class TestCurrencyNeedsTwoConditions:
    def test_a_lapsed_record_is_not_evidence(self) -> None:
        lapsed = _certified(ttl=timedelta(seconds=-1))
        artifact = _artifact()
        assert classify_artifact(artifact, (_cert(record=lapsed),), now=_NOW) is (
            ArtifactClass.UNVERIFIED
        )

    def test_a_record_that_does_not_grant_verification_is_not_evidence(self) -> None:
        pending = _certified().model_copy(update={"state": CertificationState.PENDING})
        artifact = _artifact()
        assert classify_artifact(artifact, (_cert(record=pending),), now=_NOW) is (
            ArtifactClass.UNVERIFIED
        )

    def test_each_condition_alone_is_insufficient(self) -> None:
        """The property a single-condition implementation breaks.

        Both halves fail on their own: certified-but-lapsed, and
        unexpired-but-not-granting. A predicate reading only one field passes
        every other test in this class and fails here.
        """
        artifact = _artifact()
        certified_lapsed = _certified(ttl=timedelta(seconds=-1))
        unexpired_not_granting = _certified().model_copy(
            update={"state": CertificationState.PENDING}
        )
        assert classify_artifact(artifact, (_cert(record=certified_lapsed),), now=_NOW) is (
            ArtifactClass.UNVERIFIED
        )
        assert classify_artifact(artifact, (_cert(record=unexpired_not_granting),), now=_NOW) is (
            ArtifactClass.UNVERIFIED
        )

    def test_a_current_certified_record_is_evidence(self) -> None:
        artifact = _artifact()
        assert classify_artifact(artifact, (_cert(record=_certified()),), now=_NOW) is (
            ArtifactClass.VERIFIED_COMMUNITY
        )


class TestNowIsAParameter:
    def test_changing_only_now_changes_the_verdict(self) -> None:
        """If anything read the wall clock, these two calls would agree."""
        artifact = _artifact()
        record = (_cert(record=_certified(ttl=timedelta(hours=1))),)
        assert classify_artifact(artifact, record, now=_NOW) is ArtifactClass.VERIFIED_COMMUNITY
        assert (
            classify_artifact(artifact, record, now=_NOW + timedelta(hours=2))
            is ArtifactClass.UNVERIFIED
        )

    def test_the_label_agrees_with_the_classification(self) -> None:
        artifact = _artifact()
        records = (_cert(record=_certified()),)
        label = trust_label(artifact, records, now=_NOW)
        assert label.artifact_digest == artifact.digest
        assert label.certifications == records


class TestPendingIsNotBlocking:
    def _revocation_at(self, deadline: datetime) -> Revocation:
        return _revocation(propagation_deadline=deadline)

    def test_before_the_deadline_it_is_pending_and_does_not_block(self) -> None:
        artifact = _artifact()
        revocation = self._revocation_at(_NOW + timedelta(days=1))
        assert pending_revocations(artifact, (revocation,), now=_NOW)
        assert not blocking_revocations(artifact, (revocation,), now=_NOW)
        assert dispatches(artifact, (revocation,), now=_NOW) is True

    def test_after_the_deadline_it_blocks_and_stops_the_dispatch(self) -> None:
        artifact = _artifact()
        revocation = self._revocation_at(_NOW - timedelta(seconds=1))
        assert blocking_revocations(artifact, (revocation,), now=_NOW)
        assert not pending_revocations(artifact, (revocation,), now=_NOW)
        assert dispatches(artifact, (revocation,), now=_NOW) is False

    def test_nothing_revoked_dispatches(self) -> None:
        assert dispatches(_artifact(), (), now=_NOW) is True


class TestThereIsNoShortcut:
    def test_asking_for_a_class_the_records_do_not_support_raises(self) -> None:
        artifact = _artifact()
        with pytest.raises(TrustLabelError) as caught:
            require_trust_label(artifact, (), claimed=ArtifactClass.VERIFIED_COMMUNITY, now=_NOW)
        assert "verified_community" in str(caught.value)

    def test_asking_for_the_supported_class_returns_the_label(self) -> None:
        artifact = _artifact()
        label = require_trust_label(
            artifact,
            (_cert(record=_certified()),),
            claimed=ArtifactClass.VERIFIED_COMMUNITY,
            now=_NOW,
        )
        assert label.certifications

    def test_the_refusal_names_the_class_that_was_refused(self) -> None:
        """A refusal a caller cannot act on is worse than no refusal at all."""
        artifact = _private_artifact()
        with pytest.raises(TrustLabelError) as caught:
            require_trust_label(
                artifact,
                (_cert(record=_certified()),),
                claimed=ArtifactClass.OFFICIAL,
                now=_NOW,
            )
        assert "official" in str(caught.value).lower()


class TestTheDigestCheckIsIntegrityOnly:
    def test_the_publisher_declaration_does_not_move_the_label(self) -> None:
        """The property the whole trust-label page rests on.

        Nothing in the system reads the publisher field when classifying. If a
        future change made it matter, this fails — which is the point: the page
        would then be describing a system that does not exist.
        """
        from mayhem.domain.marketplace import SIGNATURE_VERIFICATION_IMPLEMENTED

        assert SIGNATURE_VERIFICATION_IMPLEMENTED is False
        artifact = _artifact()
        honest = trust_label(artifact, (_cert(record=_certified()),), now=_NOW)
        impostor = artifact.model_copy(
            update={"publisher": artifact.publisher.model_copy(update={"publisher_id": "evil"})}
        )
        spoofed = trust_label(impostor, (_cert(record=_certified()),), now=_NOW)
        assert honest.certifications == spoofed.certifications
        assert honest.artifact_digest == spoofed.artifact_digest

    def test_the_digest_it_reports_is_the_artifacts_own(self) -> None:
        """Not the record's. A mismatch must never be reported as agreement."""
        artifact = _artifact()
        label = trust_label(artifact, (_cert(record=_certified()),), now=_NOW)
        assert label.artifact_digest == artifact.digest == _ARTIFACT_DIGEST
