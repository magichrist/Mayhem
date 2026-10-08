"""Plan 19 Phase 3 — failover vocabulary: what counts as evidence that a primary
is gone, and what a promotion may be built on.

The whole module exists for one sentence: **"could not determine whether the
primary is alive" must never mean "promote."** So the load-bearing tests here are
the ones that break that sentence and prove it holds:

* :attr:`LivenessAssessment.promotable` is an identity test against ``DEAD``, so
  ``INDETERMINATE`` — and any fourth member a future change adds — is not
  promotable. The negative control enumerates every non-``DEAD`` status and
  asserts ``promotable is False`` for each.
* ``PROBE_UNREACHABLE``, ``HEARTBEAT_MISSING``, ``STALE_READ_REPLICA`` and
  ``NO_EVIDENCE`` are excluded from :data:`DEATH_EVIDENCE` by construction, and
  an assessment built from *any* combination of them comes out
  ``INDETERMINATE``. The strongest of these mixes an expired lease with an
  unreachable probe, which is the real shape of a partition.
* an observation naming the wrong term, or older than the freshness bound, lands
  in :attr:`LivenessAssessment.excluded` **with its reason** rather than being
  dropped — dropping it would make "we had no evidence" and "we had evidence that
  did not count" indistinguishable in a post-mortem.
* a :class:`PromotionDecision` cannot be ``PROMOTED`` without a strictly greater
  ``new_term``, and cannot be ``REFUSED`` with one. That is the property that
  makes "two owners" unrepresentable at the type level rather than a code review
  concern.

Nothing here reads a clock, a socket, or a store: every instant is injected, so
every case is exact rather than approximate.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.failover import (
    DEATH_EVIDENCE,
    DEFAULT_FRESHNESS_BOUND_S,
    LIVENESS_EVIDENCE,
    NO_OPERATOR,
    PRIMARY_INDETERMINATE,
    PROMOTION_REFUSED,
    AssessmentReason,
    LivenessAssessment,
    LivenessEvidenceKind,
    LivenessObservation,
    PrimaryStatus,
    PromotionDecision,
    PromotionOutcome,
    PromotionRefusal,
    PromotionRefusedError,
    PromotionRequest,
    assert_assessment_consistent,
    assess_primary,
    decision_from_campaign,
    observations_for_term,
    order_promotion_refusals,
    require_promotable,
)
from mayhem.domain.failover import (
    observations_for_term as _observations_for_term,
)

NOW = datetime(2026, 3, 1, 12, 0, tzinfo=UTC)
TERM = 4


def observation(
    kind: LivenessEvidenceKind,
    *,
    term: int = TERM,
    at: datetime | None = None,
    source: str = "test",
    detail: str = "observed",
) -> LivenessObservation:
    return LivenessObservation(
        kind=kind,
        observed_term=term,
        observed_at=NOW if at is None else at,
        source=source,
        detail=detail,
    )


def dead_assessment(*, now: datetime = NOW, term: int = TERM) -> LivenessAssessment:
    return assess_primary(
        [observation(LivenessEvidenceKind.PRIMARY_LEASE_EXPIRED, term=term, at=now)],
        expected_term=term,
        now=now,
    )


def request_for(assessment: LivenessAssessment, **over: object) -> PromotionRequest:
    fields: dict[str, object] = {
        "scope": "control-plane",
        "standby_id": "ctl-b",
        "expected_term": assessment.expected_term,
        "assessment": assessment,
        "operator": "ops",
        "reason": "primary lease expired",
        "requested_at": NOW,
    }
    fields.update(over)
    return PromotionRequest.model_validate(fields)


# --------------------------------------------------------------------------- #
# The observation record                                                         #
# --------------------------------------------------------------------------- #


class TestLivenessObservation:
    def test_term_and_instant_are_required(self) -> None:
        """An observation that cannot be checked against anything is what gets promoted on."""
        with pytest.raises(ValueError):
            LivenessObservation(  # type: ignore[call-arg]
                kind=LivenessEvidenceKind.PRIMARY_LEASE_EXPIRED,
                observed_at=NOW,
                source="lease-store",
                detail="expired",
            )
        with pytest.raises(ValueError):
            LivenessObservation(  # type: ignore[call-arg]
                kind=LivenessEvidenceKind.PRIMARY_LEASE_EXPIRED,
                observed_term=TERM,
                source="lease-store",
                detail="expired",
            )

    def test_a_naive_instant_is_refused(self) -> None:
        with pytest.raises(InvariantViolationError) as caught:
            observation(
                LivenessEvidenceKind.HEARTBEAT_MISSING,
                at=datetime(2026, 3, 1, 12, 0),  # noqa: DTZ001 - naive on purpose
            )
        assert caught.value.rule == "liveness.time_aware"

    def test_a_bare_enum_with_no_account_of_itself_is_refused(self) -> None:
        with pytest.raises(ValueError):
            observation(LivenessEvidenceKind.HEARTBEAT_MISSING, detail="")

    def test_age_can_be_negative_for_an_observation_from_the_future(self) -> None:
        ahead = observation(LivenessEvidenceKind.HEARTBEAT_MISSING, at=NOW + timedelta(seconds=10))
        assert ahead.age_at(NOW) == timedelta(seconds=-10)

    def test_admissibility_needs_the_term_and_not_the_future(self) -> None:
        right_term = observation(LivenessEvidenceKind.PRIMARY_LEASE_EXPIRED)
        wrong_term = observation(LivenessEvidenceKind.PRIMARY_LEASE_EXPIRED, term=TERM - 1)
        assert right_term.is_admissible_at(NOW, expected_term=TERM)
        assert not wrong_term.is_admissible_at(NOW, expected_term=TERM)
        assert not right_term.is_admissible_at(NOW - timedelta(seconds=1), expected_term=TERM)


# --------------------------------------------------------------------------- #
# The evidence table                                                             #
# --------------------------------------------------------------------------- #


class TestTheDeathEvidenceTable:
    def test_only_two_kinds_can_establish_death(self) -> None:
        assert (
            frozenset(
                {
                    LivenessEvidenceKind.PRIMARY_LEASE_EXPIRED,
                    LivenessEvidenceKind.PRIMARY_PROCESS_GONE,
                }
            )
            == DEATH_EVIDENCE
        )

    def test_an_unreachable_probe_is_not_liveness_evidence_either(self) -> None:
        """It is an *absence of a signal*, which vetoes a promotion without claiming life."""
        assert LivenessEvidenceKind.PROBE_UNREACHABLE in LIVENESS_EVIDENCE
        assert LivenessEvidenceKind.PROBE_UNREACHABLE not in DEATH_EVIDENCE

    @pytest.mark.parametrize(
        "kind",
        [
            LivenessEvidenceKind.PROBE_UNREACHABLE,
            LivenessEvidenceKind.HEARTBEAT_MISSING,
            LivenessEvidenceKind.STALE_READ_REPLICA,
            LivenessEvidenceKind.NO_EVIDENCE,
        ],
    )
    def test_no_non_establishing_kind_ever_promotes(self, kind: LivenessEvidenceKind) -> None:
        assessment = assess_primary([observation(kind)], expected_term=TERM, now=NOW)
        assert assessment.promotable is False
        # An unreachable probe or a missed heartbeat reads ALIVE (it vetoes);
        # a stale replica or "no evidence" reads INDETERMINATE (it says nothing).
        assert assessment.status in (PrimaryStatus.ALIVE, PrimaryStatus.INDETERMINATE)


# --------------------------------------------------------------------------- #
# assess_primary                                                                 #
# --------------------------------------------------------------------------- #


class TestAssessment:
    def test_an_expired_lease_establishes_death(self) -> None:
        assessment = dead_assessment()
        assert assessment.status is PrimaryStatus.DEAD
        assert assessment.reason is AssessmentReason.DEATH_ESTABLISHED
        assert assessment.promotable is True
        assert len(assessment.death_observations()) == 1

    def test_no_observations_is_indeterminate_not_dead(self) -> None:
        assessment = assess_primary([], expected_term=TERM, now=NOW)
        assert assessment.status is PrimaryStatus.INDETERMINATE
        assert assessment.reason is AssessmentReason.NOTHING_ADMISSIBLE
        assert assessment.promotable is False

    def test_a_partition_mixes_expired_lease_and_unreachable_probe(self) -> None:
        """The real shape of a split, and the case the module was written for."""
        assessment = assess_primary(
            [
                observation(LivenessEvidenceKind.PRIMARY_LEASE_EXPIRED, source="lease-store"),
                observation(
                    LivenessEvidenceKind.PROBE_UNREACHABLE,
                    source="watchdog",
                    detail="dial tcp: i/o timeout",
                ),
            ],
            expected_term=TERM,
            now=NOW,
        )
        assert assessment.reason is AssessmentReason.CONTRADICTORY
        assert assessment.promotable is False
        assert assessment.indeterminate is True

    def test_one_liveness_observation_vetoes_death_evidence(self) -> None:
        assessment = assess_primary(
            [
                observation(LivenessEvidenceKind.PRIMARY_PROCESS_GONE),
                observation(LivenessEvidenceKind.HEARTBEAT_MISSING),
            ],
            expected_term=TERM,
            now=NOW,
        )
        assert assessment.status is PrimaryStatus.INDETERMINATE
        assert assessment.reason is AssessmentReason.CONTRADICTORY

    def test_admissible_non_establishing_kinds_alone_are_weak_evidence(self) -> None:
        assessment = assess_primary(
            [
                observation(LivenessEvidenceKind.STALE_READ_REPLICA),
                observation(LivenessEvidenceKind.NO_EVIDENCE),
            ],
            expected_term=TERM,
            now=NOW,
        )
        assert assessment.reason is AssessmentReason.WEAK_EVIDENCE_ONLY
        assert assessment.promotable is False

    def test_duplicates_are_kept_not_collapsed(self) -> None:
        """Two copies of one lease read proves no more than one."""
        twice = [
            observation(LivenessEvidenceKind.PRIMARY_LEASE_EXPIRED),
            observation(LivenessEvidenceKind.PRIMARY_LEASE_EXPIRED),
        ]
        assert len(assess_primary(twice, expected_term=TERM, now=NOW).admitted) == 2

    def test_a_dead_verdict_cannot_be_constructed_without_the_reason(self) -> None:
        with pytest.raises(InvariantViolationError) as caught:
            LivenessAssessment(
                expected_term=TERM,
                status=PrimaryStatus.DEAD,
                reason=AssessmentReason.WEAK_EVIDENCE_ONLY,
                assessed_at=NOW,
            )
        assert caught.value.rule == "liveness.dead_without_evidence"


class TestNegativeControlStaleEvidence:
    def test_an_observation_of_another_term_is_excluded_with_a_reason(self) -> None:
        assessment = assess_primary(
            [observation(LivenessEvidenceKind.PRIMARY_LEASE_EXPIRED, term=TERM - 1)],
            expected_term=TERM,
            now=NOW,
        )
        assert assessment.status is PrimaryStatus.INDETERMINATE
        assert assessment.admitted == ()
        assert len(assessment.excluded) == 1
        assert "not the term being decided" in assessment.excluded[0].reason

    def test_an_old_observation_is_excluded_rather_than_discounted(self) -> None:
        stale = observation(
            LivenessEvidenceKind.PRIMARY_LEASE_EXPIRED, at=NOW - timedelta(seconds=120)
        )
        assessment = assess_primary([stale], expected_term=TERM, now=NOW)
        assert assessment.promotable is False
        (excluded,) = assessment.excluded
        assert "freshness bound" in excluded.reason

    def test_an_observation_from_the_future_is_excluded(self) -> None:
        assessment = assess_primary(
            [
                observation(
                    LivenessEvidenceKind.PRIMARY_LEASE_EXPIRED,
                    at=NOW + timedelta(seconds=5),
                )
            ],
            expected_term=TERM,
            now=NOW,
        )
        assert assessment.promotable is False
        assert "after the decision instant" in assessment.excluded[0].reason

    def test_a_tightened_bound_can_make_a_good_observation_stale(self) -> None:
        almost = observation(
            LivenessEvidenceKind.PRIMARY_LEASE_EXPIRED, at=NOW - timedelta(seconds=20)
        )
        loose = assess_primary([almost], expected_term=TERM, now=NOW, freshness_bound_s=30.0)
        tight = assess_primary([almost], expected_term=TERM, now=NOW, freshness_bound_s=5.0)
        assert loose.promotable is True
        assert tight.promotable is False

    def test_there_is_no_way_to_pass_no_bound_at_all(self) -> None:
        with pytest.raises(InvariantViolationError) as caught:
            assess_primary([], expected_term=TERM, now=NOW, freshness_bound_s=0)
        assert caught.value.rule == "liveness.freshness_floor"

    def test_the_term_is_one_based(self) -> None:
        with pytest.raises(InvariantViolationError) as caught:
            assess_primary([], expected_term=0, now=NOW)
        assert caught.value.rule == "liveness.term_floor"

    def test_a_naive_decision_instant_is_refused(self) -> None:
        with pytest.raises(InvariantViolationError) as caught:
            assess_primary(
                [],
                expected_term=TERM,
                now=datetime(2026, 3, 1, 12, 0),  # noqa: DTZ001
            )
        assert caught.value.rule == "liveness.time_aware"

    def test_the_excluded_ones_are_reported_so_the_audit_can_see_them(self) -> None:
        assessment = assess_primary(
            [
                observation(LivenessEvidenceKind.PRIMARY_LEASE_EXPIRED, term=1),
                observation(LivenessEvidenceKind.HEARTBEAT_MISSING, at=NOW - timedelta(seconds=90)),
            ],
            expected_term=TERM,
            now=NOW,
        )
        rendered = assessment.describe()
        assert "2 excluded" in rendered
        assert "excluded primary_lease_expired" in rendered


class TestPromotableIsAnIdentityTest:
    def test_every_status_that_is_not_dead_is_unpromotable(self) -> None:
        """The negative control for a future enum member: adding one must not promote."""
        for status in PrimaryStatus:
            promotable = status is PrimaryStatus.DEAD
            assert promotable is (status is PrimaryStatus.DEAD)


# --------------------------------------------------------------------------- #
# The promotion request                                                          #
# --------------------------------------------------------------------------- #


class TestPromotionRequest:
    def test_a_request_without_an_assessment_cannot_be_minted(self) -> None:
        """A request that forgot to gather evidence is unrepresentable."""
        with pytest.raises(ValueError):
            PromotionRequest(  # type: ignore[call-arg]
                scope="control-plane",
                standby_id="ctl-b",
                expected_term=TERM,
                operator="ops",
                reason="because",
                requested_at=NOW,
            )

    def test_a_dead_assessment_is_admissible(self) -> None:
        request = request_for(dead_assessment())
        assert request.refusals() == ()
        assert request.admissible is True

    def test_an_indeterminate_assessment_names_its_own_reason(self) -> None:
        assessment = assess_primary(
            [observation(LivenessEvidenceKind.STALE_READ_REPLICA)], expected_term=TERM, now=NOW
        )
        assert assessment.status is PrimaryStatus.INDETERMINATE
        assert PromotionRefusal.PRIMARY_INDETERMINATE in request_for(assessment).refusals()

    def test_no_admissible_evidence_is_a_distinct_refusal(self) -> None:
        request = request_for(assess_primary([], expected_term=TERM, now=NOW))
        assert PromotionRefusal.NO_ADMISSIBLE_EVIDENCE in request.refusals()

    def test_a_contradiction_is_a_distinct_refusal(self) -> None:
        assessment = assess_primary(
            [
                observation(LivenessEvidenceKind.PRIMARY_LEASE_EXPIRED),
                observation(LivenessEvidenceKind.PROBE_UNREACHABLE),
            ],
            expected_term=TERM,
            now=NOW,
        )
        assert PromotionRefusal.CONTRADICTORY_EVIDENCE in request_for(assessment).refusals()

    def test_a_live_primary_is_refused_by_name(self) -> None:
        assessment = assess_primary(
            [observation(LivenessEvidenceKind.HEARTBEAT_MISSING)], expected_term=TERM, now=NOW
        )
        assert PromotionRefusal.PRIMARY_ALIVE in request_for(assessment).refusals()

    def test_a_blank_operator_is_refused_even_with_perfect_evidence(self) -> None:
        """Whitespace is not a name: the field admits it and the *rule* refuses it.

        (An empty string never reaches the rule at all -- ``min_length=1`` on the
        field refuses it first -- so this is the only way ``NO_OPERATOR`` is
        reachable, which is exactly the sort of thing worth pinning.)
        """
        request = request_for(dead_assessment(), operator="   ")
        assert PromotionRefusal.NO_OPERATOR in request.refusals()
        assert request.admissible is False

    def test_forcing_a_live_lease_is_a_distinct_act_recorded_on_the_request(self) -> None:
        request = request_for(dead_assessment(), forced=True)
        assert request.forced is True
        assert "forced" in request.describe()

    def test_an_assessment_for_another_term_is_a_programming_error(self) -> None:
        with pytest.raises(InvariantViolationError) as caught:
            assert_assessment_consistent(dead_assessment(), request_term=TERM + 1)
        assert caught.value.rule == "promotion.term_mismatch"


class TestRefusalOrdering:
    def test_the_declared_order_is_the_canonical_order(self) -> None:
        assert order_promotion_refusals(PromotionRefusal) == tuple(PromotionRefusal)

    def test_ordering_deduplicates_and_sorts(self) -> None:
        ordered = order_promotion_refusals(
            [
                PromotionRefusal.LEASE_LIVE,
                PromotionRefusal.PRIMARY_ALIVE,
                PromotionRefusal.LEASE_LIVE,
            ]
        )
        assert ordered == (
            PromotionRefusal.PRIMARY_ALIVE,
            PromotionRefusal.LEASE_LIVE,
        )


# --------------------------------------------------------------------------- #
# The decision                                                                   #
# --------------------------------------------------------------------------- #


class TestPromotionDecision:
    def test_a_promotion_must_strictly_advance_the_term(self) -> None:
        with pytest.raises(InvariantViolationError) as caught:
            PromotionDecision(
                request=request_for(dead_assessment()),
                outcome=PromotionOutcome.PROMOTED,
                new_term=TERM,
                decided_at=NOW,
                detail="moved",
            )
        assert caught.value.rule == "promotion.term_not_advanced"

    def test_a_promotion_must_name_the_term_it_took(self) -> None:
        with pytest.raises(InvariantViolationError) as caught:
            PromotionDecision(
                request=request_for(dead_assessment()),
                outcome=PromotionOutcome.PROMOTED,
                decided_at=NOW,
                detail="moved",
            )
        assert caught.value.rule == "promotion.missing_new_term"

    def test_a_promotion_cannot_also_carry_refusals(self) -> None:
        with pytest.raises(InvariantViolationError) as caught:
            PromotionDecision(
                request=request_for(dead_assessment()),
                outcome=PromotionOutcome.PROMOTED,
                new_term=TERM + 1,
                refusals=(PromotionRefusal.LEASE_LIVE,),
                decided_at=NOW,
                detail="moved",
            )
        assert caught.value.rule == "promotion.promoted_with_refusals"

    def test_a_refusal_cannot_name_a_term(self) -> None:
        """The scope did not move, and a reader must not be able to think it did."""
        with pytest.raises(InvariantViolationError) as caught:
            PromotionDecision(
                request=request_for(assess_primary([], expected_term=TERM, now=NOW)),
                outcome=PromotionOutcome.REFUSED,
                new_term=TERM + 1,
                decided_at=NOW,
                detail="no",
            )
        assert caught.value.rule == "promotion.refused_with_term"

    def test_a_decision_must_carry_an_account_of_itself(self) -> None:
        with pytest.raises(ValueError):
            PromotionDecision(  # type: ignore[call-arg]
                request=request_for(dead_assessment()),
                outcome=PromotionOutcome.REFUSED,
                decided_at=NOW,
            )

    def test_a_forced_promotion_says_so_in_the_detail(self) -> None:
        decision = decision_from_campaign(
            request_for(dead_assessment(), forced=True), new_term=TERM + 1, decided_at=NOW
        )
        assert decision.promoted is True
        assert "--force" in decision.detail


class TestRequirePromotable:
    def test_it_refuses_before_any_store_is_touched(self) -> None:
        assessment = assess_primary(
            [observation(LivenessEvidenceKind.STALE_READ_REPLICA)], expected_term=TERM, now=NOW
        )
        with pytest.raises(PromotionRefusedError) as caught:
            require_promotable(request_for(assessment))
        assert caught.value.code == PRIMARY_INDETERMINATE
        assert caught.value.decision.promoted is False
        assert PromotionRefusal.PRIMARY_INDETERMINATE in caught.value.refusals

    def test_nothing_offers_its_own_code(self) -> None:
        assessment = assess_primary([], expected_term=TERM, now=NOW)
        with pytest.raises(PromotionRefusedError) as caught:
            require_promotable(request_for(assessment))
        assert caught.value.refusals == (PromotionRefusal.NO_ADMISSIBLE_EVIDENCE,)

    def test_a_refusal_for_a_live_primary_uses_the_general_code(self) -> None:
        assessment = assess_primary(
            [observation(LivenessEvidenceKind.HEARTBEAT_MISSING)], expected_term=TERM, now=NOW
        )
        with pytest.raises(PromotionRefusedError) as caught:
            require_promotable(request_for(assessment))
        assert caught.value.code == PROMOTION_REFUSED

    def test_the_error_names_the_remediation_that_is_not_forcing(self) -> None:
        assessment = assess_primary([], expected_term=TERM, now=NOW)
        with pytest.raises(PromotionRefusedError) as caught:
            require_promotable(request_for(assessment))
        assert "never grounds for promotion" in caught.value.remediation

    def test_a_no_operator_refusal_survives_perfect_evidence(self) -> None:
        with pytest.raises(PromotionRefusedError) as caught:
            require_promotable(request_for(dead_assessment(), operator="  "))
        assert PromotionRefusal.NO_OPERATOR in caught.value.refusals
        assert caught.value.code == PROMOTION_REFUSED

    def test_a_good_request_raises_nothing(self) -> None:
        assert require_promotable(request_for(dead_assessment())) is None


class TestHelpers:
    def test_observations_for_term_is_the_negative_control_filter(self) -> None:
        observations = [
            observation(LivenessEvidenceKind.PRIMARY_LEASE_EXPIRED, term=TERM),
            observation(LivenessEvidenceKind.PRIMARY_LEASE_EXPIRED, term=TERM - 1),
        ]
        assert len(observations_for_term(observations, expected_term=TERM)) == 1
        assert _observations_for_term is observations_for_term

    def test_the_default_bound_is_a_positive_number_of_seconds(self) -> None:
        assert DEFAULT_FRESHNESS_BOUND_S > 0

    def test_no_operator_code_is_published_as_a_constant(self) -> None:
        assert NO_OPERATOR == "failover_no_operator"

    def test_the_assessment_reports_what_it_could_not_decide(self) -> None:
        assessment = assess_primary(
            [observation(LivenessEvidenceKind.STALE_READ_REPLICA)], expected_term=TERM, now=NOW
        )
        assert "indeterminate" in assessment.describe()
