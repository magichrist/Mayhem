"""Plan 06 Phase 4 — the cloud admission gate and its sealed evidence.

The acceptance this suite pins, in the plan's own words: *an action exceeding
the cost ceiling refuses before mutation*. The negative control for that is a
counting transport: the gate never receives one that works, and every refusal
test asserts the mutation count stayed at zero.
"""

from __future__ import annotations

from dataclasses import FrozenInstanceError
from datetime import UTC, datetime
from decimal import Decimal
from typing import TYPE_CHECKING

import pytest

from mayhem.controller.cloud_evidence import (
    CLOUD_ADMISSION_NOTICE,
    CLOUD_NO_REGION_BLAST_RULES_NOTE,
    CloudAdmissionOutcome,
    CloudGateStage,
    admit_cloud_action,
    cloud_chain_key,
    decision_chain_events,
    load_cloud_decisions,
    seal_cloud_decision,
    verify_cloud_decision_chain,
)
from mayhem.domain.attestation import AttestedTimestamp
from mayhem.domain.budgets import ResourceScope
from mayhem.domain.cloud import (
    CLOUD_COST_CEILING_EXCEEDED,
    CloudActionKind,
    CloudProvider,
    CloudProviderRef,
    CloudResourceClass,
    CloudResourceIdentity,
    CloudRoleRef,
    CloudSelector,
    CloudSelectorKind,
    CloudTarget,
    CostEstimate,
    Reversibility,
    ReversibleCloudAction,
)
from mayhem.domain.provider import ProviderPermission
from mayhem.domain.quota import UNRESOLVED_FAULT_WEIGHT, DamageLedger, DamageQuota
from mayhem.infra.attestation_store import AttestationError
from mayhem.infra.migrations import ALL_MIGRATIONS
from mayhem.infra.store import Store
from mayhem.providers.cloud.aws import AwsCloudAdapter
from mayhem.providers.cloud.port import (
    CloudRateCard,
    MutationCommand,
    MutationReceipt,
    ResourceQuery,
    ResourceRecord,
)
from mayhem.providers.participation import ProviderParticipationError

if TYPE_CHECKING:  # pragma: no cover
    from pathlib import Path

    from mayhem.providers.cloud.port import CloudAdapter

GRAANTS_ALL = frozenset(
    {
        ProviderPermission.TARGET_MUTATE,
        ProviderPermission.TARGET_READ,
        ProviderPermission.NETWORK,
    }
)


def _roomy_quota() -> DamageQuota:
    """The default quota with its caps lifted.

    Named for the ceiling the default makes impossible: a 3600s reversible
    cloud stop charges 28800 damage-seconds at the conservative top rung, and
    the default per-fault ceiling is 3600. Tests that need the *default*
    quota back pass ``quota=DamageQuota()`` explicitly — the refusals it
    makes are the damage stage's own tests.
    """
    return DamageQuota(budget_s=1_000_000.0, per_fault_ceiling_s=1_000_000.0)


# =============================================================================
# Fixtures
# =============================================================================


class _CountingTransport:
    """A transport that counts mutations and never lets one through.

    The negative control. Implements :class:`CloudTransport` structurally, so
    the adapter *could* act through it — but every ``mutate`` counts and then
    refuses, so a gate that mutated names itself here.
    """

    def __init__(self) -> None:
        self.mutations = 0

    def list_resources(self, query: ResourceQuery) -> tuple[ResourceRecord, ...]:
        return ()

    def read_resource(self, query: ResourceQuery, resource_id: str) -> ResourceRecord | None:
        return None

    def mutate(self, command: MutationCommand) -> MutationReceipt:
        self.mutations += 1
        raise AssertionError(f"the gate must never mutate; got {command.subject}")


def _open_store(tmp_path: Path) -> Store:
    """The same minimal store the Kubernetes evidence lane seals over."""
    return Store.open_migrated(tmp_path / "mayhem.db", migrations=ALL_MIGRATIONS)


def _reading() -> AttestedTimestamp:
    """A fixed wall/monotonic pair, so sealed records are reproducible."""
    return AttestedTimestamp(
        wall_clock=datetime(2026, 10, 7, 12, 0, tzinfo=UTC),
        monotonic_ns=7,
        uncertainty_ms=0.0,
        source="test-fixed",
    )


def _action(
    kind: CloudActionKind = CloudActionKind.STOP, duration_s: float = 3600.0
) -> ReversibleCloudAction:
    """A reversible AWS vm stop — the same shape ``cloud_cmd.py`` builds."""
    ref = CloudProviderRef(provider=CloudProvider.AWS)
    identity = CloudResourceIdentity(
        provider=ref,
        resource_class=CloudResourceClass.VM,
        account="123456789012",
        region="us-east-1",
        resource_id="i-0abc",
    )
    selector = CloudSelector(
        resource_class=CloudResourceClass.VM,
        kind=CloudSelectorKind.IDENTIFIER,
        account="123456789012",
        region="us-east-1",
        identifiers=("i-0abc",),
    )
    target = CloudTarget(
        provider=ref,
        resource_class=CloudResourceClass.VM,
        selector=selector,
        identity=identity,
    )
    return ReversibleCloudAction(
        action_id="probe.aws.vm.stop",
        kind=kind,
        target=target,
        summary="phase 4 admission probe",
        reversibility=Reversibility.REVERSIBLE,
        duration_s=duration_s,
        required_permissions=frozenset(
            {ProviderPermission.TARGET_MUTATE, ProviderPermission.TARGET_READ}
        ),
    )


def _rates() -> tuple[CloudRateCard, ...]:
    """An operator rate card for aws/us-east-1 vm — the only priced estimates."""
    return (
        CloudRateCard(
            provider=CloudProviderRef(provider=CloudProvider.AWS),
            resource_class=CloudResourceClass.VM,
            region="us-east-1",
            source="test: unit rate card",
            micros_per_api_call=float(Decimal("1")),
            micros_per_instance_hour=float(Decimal("5000")),
            micros_per_volume_operation=float(Decimal("0")),
            high_factor=1.0,
        ),
    )


def _admit(
    *,
    action: ReversibleCloudAction | None = None,
    ceiling: float = 1_000_000.0,
    duration: float = 3600.0,
    spend: float | None = None,
    grants: frozenset[ProviderPermission] | None = None,
    quota: DamageQuota | None = None,
    ledger: DamageLedger | None = None,
    rate_cards: tuple[CloudRateCard, ...] | None = None,
) -> tuple[CloudAdmissionOutcome, _CountingTransport]:
    """One admission call with everything wired, returning the transport too."""
    # The default quota lifts the damage caps, because every cost-stage and
    # honesty test below wants the two cheaper stages *not to be the refuser*:
    # a 3600s step at the conservative top rung charges 28800 damage-seconds,
    # which the real DamageQuota defaults refuse. The quota tests override
    # this with the default quota — the interesting admission refusals are
    # exactly the ones the default quota makes.
    effective_quota = quota if quota is not None else _roomy_quota()
    transport = _CountingTransport()
    adapter: CloudAdapter = AwsCloudAdapter(
        transport, rate_cards=_rates() if rate_cards is None else rate_cards
    )
    outcome = admit_cloud_action(
        adapter,
        action if action is not None else _action(),
        CloudRoleRef(
            role_id="declared.operator",
            provider=CloudProviderRef(provider=CloudProvider.AWS),
            granted=GRAANTS_ALL if grants is None else grants,
        ),
        run_id="run-1",
        owner_agent="agent",
        duration_s=duration,
        ceiling=ceiling,
        quota=effective_quota,
        ledger=ledger or DamageLedger(),
        projected_spend=spend,
    )
    return outcome, transport


def _ceiling_boundary() -> CostEstimate:
    """A hand-built priced estimate that a ceiling of 5004 barely covers.

    Same numbers the aws/vm rate card produces for a 3600s reversible stop:
    4 api calls + 1 billable instance-hour. Used to assert the ceiling
    boundary behaviour on a shape this module derives, not authors.
    """
    return CostEstimate(
        scope=ResourceScope.EXPERIMENT,
        scope_key="123456789012",
        expected_low=5004.0,
        expected_high=5004.0,
        ceiling=5004.0,
        basis="priced from operator rate card source='test'; 4 api calls + 1 h",
    )


# =============================================================================
# Stage 1 — permission
# =============================================================================


class TestPermissionStage:
    """The gate refuses an IAM gap by name, before any price is computed."""

    def test_refusal_names_the_missing_permission(self) -> None:
        """The plan's Phase 3 bar, repinned on the gate: the name, not a boolean."""
        outcome, transport = _admit(grants=frozenset({ProviderPermission.TARGET_READ}))
        assert outcome.refused
        assert outcome.stage is CloudGateStage.PERMISSION
        assert "target:mutate" in outcome.reason
        assert outcome.rule_id
        # Refused before reaching any later stage:
        assert outcome.preview is None
        assert outcome.blast is None
        assert transport.mutations == 0

    def test_role_provider_mismatch_refuses_at_the_gate(self) -> None:
        """A gcp role cannot run an aws action — the same cloud's boundary."""
        outcome, transport = _admit(
            grants=GRAANTS_ALL,
            action=_action(),
        )
        gcp_role = CloudRoleRef(
            role_id="declared.gcp.viewer",
            provider=CloudProviderRef(provider=CloudProvider.GCP),
            granted=GRAANTS_ALL,
        )
        transport2 = _CountingTransport()
        adapter: CloudAdapter = AwsCloudAdapter(transport2, rate_cards=_rates())
        outcome2 = admit_cloud_action(
            adapter,
            _action(),
            gcp_role,
            run_id="run-1",
            owner_agent="agent",
            duration_s=3600.0,
            ceiling=1_000_000.0,
            quota=DamageQuota(),
            ledger=DamageLedger(),
        )
        assert outcome2.refused
        assert outcome2.stage is CloudGateStage.PERMISSION
        assert outcome2.preview is None
        assert transport2.mutations == 0
        del outcome, transport  # the first admission is needed only as wiring


# =============================================================================
# Stage 2 — cost, and the acceptance refusal
# =============================================================================


class TestCostStage:
    """Cost refusals, including the acceptance refusal, mutate nothing."""

    def test_unpriced_action_with_a_declared_ceiling_refuses(self) -> None:
        """``cloud.cost_unpriced``: an action nobody can price fits no limit."""
        outcome, transport = _admit(rate_cards=())
        assert outcome.refused
        assert outcome.stage is CloudGateStage.COST
        assert "cloud.cost_unpriced" in outcome.rule_id
        assert transport.mutations == 0

    def test_unpriced_without_ceiling_admits_with_honest_zeros(self) -> None:
        """No price is known, not that the action is free — the Phase 3 honesty."""
        outcome, transport = _admit(rate_cards=(), ceiling=0.0)
        assert outcome.admitted
        assert outcome.stage is CloudGateStage.NONE
        assert outcome.preview is not None and outcome.preview.priced is False
        assert transport.mutations == 0

    def test_an_action_exceeding_the_ceiling_refuses_before_mutation(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """THE acceptance: refused before anything mutated."""
        outcome, transport = _admit(ceiling=1000.0, spend=500_000.0)
        assert outcome.refused
        assert outcome.stage is CloudGateStage.COST
        assert CLOUD_COST_CEILING_EXCEEDED in outcome.rule_id
        assert transport.mutations == 0
        del capsys  # no output contract here — the gate returns, not prints

    def test_ceiling_below_the_estimate_high_bound_refuses(self) -> None:
        """``cloud.cost_ceiling_below_high``: the plan is already over budget."""
        # The rate card prices the probe at 4 api-calls only (a stopped EC2
        # instance bills no compute), so a ceiling of 2 is below the 4-high.
        outcome, transport = _admit(ceiling=2.0)
        assert outcome.refused
        assert outcome.stage is CloudGateStage.COST
        assert "cloud.cost_ceiling_below_high" in outcome.rule_id
        assert transport.mutations == 0

    def test_projected_spend_over_ceiling_refuses_even_when_estimate_fits(self) -> None:
        """The plan declares it may cost this much; the ceiling disagrees."""
        outcome, transport = _admit(ceiling=100.0, spend=5_600.0)
        assert outcome.refused
        assert outcome.stage is CloudGateStage.COST
        assert CLOUD_COST_CEILING_EXCEEDED in outcome.rule_id
        assert transport.mutations == 0


# =============================================================================
# Stage 3 — the shared damage ledger
# =============================================================================


class TestDamageQuotaStage:
    """The ledger is the shared one; the weight is the conservative top rung."""

    def test_admitted_action_charges_the_shared_ledger(self) -> None:
        """A permitted action lands on the ledger like any native charge."""
        ledger = DamageLedger()
        outcome, transport = _admit(ledger=ledger)
        assert outcome.admitted
        assert outcome.stage is CloudGateStage.NONE
        assert transport.mutations == 0
        # Charged, priced at the conservative rung (probe.* is no catalog fault):
        assert outcome.blast is not None
        assert outcome.blast.weight == UNRESOLVED_FAULT_WEIGHT
        identity = _action().target.identity
        expected_per_node = 3600.0 * UNRESOLVED_FAULT_WEIGHT
        assert ledger.damage_for(identity.canonical_id) == pytest.approx(expected_per_node)
        assert outcome.weight_source == "unresolved_conservative"

    def test_running_total_refuses_on_budget(self) -> None:
        """Previous damage counts: the gate refuses past ``damage_quota.budget``."""
        ledger = DamageLedger()
        # Warm the ledger with a catalog-priced fault (300s LOW/REVERSIBLE =
        # 300 damage-seconds), then approach the default 14400 budget with
        # the conservative-rung cloud charge on top: (14400 - 300) / 8 = 1762s,
        # so a 1800s planned step breaches ``damage_quota.budget``.
        ledger.charge(
            fault_id="cpu.host",
            duration_s=300.0,
            node_ids=("cpu.host:0:zone-a",),
            quota=DamageQuota(),
        )
        outcome, transport = _admit(ledger=ledger, duration=1800.0, quota=DamageQuota())
        assert outcome.refused
        assert outcome.stage is CloudGateStage.DAMAGE_QUOTA
        assert "damage_quota.per_fault_ceiling" in outcome.rule_id
        assert transport.mutations == 0

    def test_per_fault_ceiling_refusal(self) -> None:
        """One huge planned step refuses on the per-fault ceiling."""
        outcome, transport = _admit(duration=2_600_000.0)
        assert outcome.refused
        assert outcome.stage is CloudGateStage.DAMAGE_QUOTA
        assert "damage_quota.per_fault_ceiling" in outcome.rule_id
        assert transport.mutations == 0

    def test_the_charge_survives_a_quota_refusal(self) -> None:
        """Charged, then judged: the refusal is on a ledger that already moved."""
        ledger = DamageLedger()
        outcome, _ = _admit(duration=2_600_000.0, ledger=ledger)
        assert outcome.refused
        identity = _action().target.identity
        assert ledger.damage_for(identity.canonical_id) > 0.0


# =============================================================================
# Honesty notes and payload contract
# =============================================================================


class TestOutcomeContract:
    """Every outcome carries the caveats a reader must not have to re-derive."""

    def test_notice_is_carried(self) -> None:
        outcome, _ = _admit()
        assert outcome.notice == CLOUD_ADMISSION_NOTICE
        assert "mutated nothing" in outcome.notice

    def test_region_blast_boundary_is_named(self) -> None:
        """``within quota`` must never read as ``regionally bounded``."""
        outcome, _ = _admit()
        assert CLOUD_NO_REGION_BLAST_RULES_NOTE in str(outcome.to_dict()["region_blast_rules"])

    def test_payload_names_the_resource_the_provider_audit_log_would(self) -> None:
        outcome, _ = _admit()
        payload = outcome.to_dict()
        identity = _action().target.identity
        assert payload["resource"] == identity.canonical_id
        assert payload["provider"] == "aws"
        assert payload["region"] == "us-east-1"
        assert payload["account"] == "123456789012"
        assert payload["action_id"] == "probe.aws.vm.stop"
        assert isinstance(payload["cost"], dict)

    def test_payload_is_json_safe(self) -> None:
        """Tuples serialize as lists; enums become their values."""
        outcome, _ = _admit()
        payload = outcome.to_dict()
        assert isinstance(payload["cost"], dict)
        assert isinstance(payload["blast"], dict)
        assert payload["kind"] == "stop"

    def test_requires_elevated_approval_is_reported(self) -> None:
        """The reversibility half of the decision is on the record, not implied."""
        outcome, _ = _admit()
        assert outcome.to_dict()["requires_elevated_approval"] is False

    def test_ceiling_boundary_witness(self) -> None:
        """The 5004 boundary: a spend exactly at the ceiling is inside it."""
        estimate = _ceiling_boundary()
        assert estimate.expected_low == 5004.0
        assert estimate.expected == 5004.0
        assert estimate.headroom == 0.0


# =============================================================================
# Sealing
# =============================================================================


class TestSealing:
    """The decisions seal through the ordinary repository; reload is exact."""

    def _sealed(self, tmp_path: Path, outcomes: list[CloudAdmissionOutcome]) -> Store:
        store = _open_store(tmp_path)
        seal = seal_cloud_decision(store, "run-1", outcomes, recorded_at=_reading())
        assert seal is not None
        assert seal.valid
        assert seal.signed is False  # integrity, never authorship (plan 12)
        return store

    def test_seal_then_load_round_trips(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        _ceiling_boundary()  # keep the estimate numbers in one place
        outcome, _ = _admit()
        store = self._sealed(tmp_path, [outcome])
        reloaded = load_cloud_decisions(store, "run-1")
        assert reloaded is not None
        assert reloaded.valid
        assert reloaded.decisions == (outcome.to_dict(),)
        # The stored chain key is the namespaced one:
        assert cloud_chain_key("run-1").endswith(":cloud-actions")
        del capsys

    def test_verify_reports_an_unsealed_run(self, tmp_path: Path) -> None:
        """Nothing stored → verifiably invalid, never silently fine."""
        store = _open_store(tmp_path)
        verification = verify_cloud_decision_chain(store, "run-other")
        assert verification.valid is False
        assert "no chain stored" in " ".join(verification.errors)

    def test_tampered_records_fail_verification(self, tmp_path: Path) -> None:
        """A resealed-but-tampered chain must not verify — integrity is the point."""
        outcome, _ = _admit()
        store = self._sealed(tmp_path, [outcome])
        from mayhem.infra.attestation_store import AttestationRepository

        repo = AttestationRepository(store)
        events = list(repo.load_chain(cloud_chain_key("run-1")))
        assert events
        tampered = [
            evt.model_copy(
                update={
                    "payload": {
                        **evt.payload,
                        "admitted": not bool(evt.payload.get("admitted")),
                    }
                }
            )
            for evt in events
        ]
        with pytest.raises(AttestationError):
            repo.save_chain(
                cloud_chain_key("run-1"),
                tuple(tampered),
                sealed_at=_reading().wall_clock,
            )
        # The resealed-but-tampered row is written below the repository's own
        # verify-then-save: the tampered event is still *valid to the verifier*
        # (it carries its own now-consistent digest), so the repository would
        # have stored it had it been asked — but the stored chain_root column
        # still holds the root of the record that was actually sealed, so
        # re-reading the stored bytes and re-verifying catches the switch. The
        # same split "each event verifies" vs "the stored row is the one that
        # was sealed" that the shared attestation suite pins.
        from mayhem.infra.attestation_store import seal_events as _seal

        resealed = _seal(tuple(tampered))[0]
        with store.write() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO attestation_events "
                "(run_id, sequence, event_id, event_kind, digest, chain_link,"
                " previous_digest, recorded_at, event_json) VALUES (?,?,?,?,?,?,?,?,?)",
                (
                    cloud_chain_key("run-1"),
                    resealed.sequence,
                    resealed.event_id,
                    resealed.event_kind,
                    resealed.digest,
                    resealed.chain_link,
                    resealed.previous_digest,
                    resealed.recorded_at.wall_clock.isoformat(),
                    resealed.model_dump_json(),
                ),
            )
        verification = verify_cloud_decision_chain(store, "run-1")
        assert verification.valid is False
        assert any("stored chain root" in error for error in verification.errors)

    def test_empty_seal_writes_nothing(self, tmp_path: Path) -> None:
        """An empty chain is not written; nothing verifies later either."""
        store = _open_store(tmp_path)
        assert seal_cloud_decision(store, "run-1", [], recorded_at=_reading()) is None
        assert verify_cloud_decision_chain(store, "run-1").valid is False

    def test_sequence_and_ids_are_ordered(self, tmp_path: Path) -> None:
        outcome, _ = _admit()
        events = decision_chain_events("run-1", [outcome], recorded_at=_reading())
        assert [e.sequence for e in events] == [0]
        assert events[0].event_id == "run-1:cloud-actions:probe.aws.vm.stop"
        assert not isinstance(events[0].run_id, dict)

    def test_events_carry_the_plan_12_clock(self) -> None:
        """One wall+monotonic pair, taken once, on every event of the chain."""
        outcome, _ = _admit()
        reading = _reading()
        events = decision_chain_events("run-1", [outcome], recorded_at=reading)
        stamps = {e.recorded_at.wall_clock for e in events}
        assert stamps == {reading.wall_clock}
        assert all(e.recorded_at.monotonic_ns == reading.monotonic_ns for e in events)


# =============================================================================
# Value-shape guards against regression
# =============================================================================


class TestAdmissionValueShapes:
    """Cheap guards: types and vocabularies the gate must not quietly widen."""

    def test_stage_vocabulary_is_closed(self) -> None:
        assert {stage.value for stage in CloudGateStage} == {
            "permission",
            "cost",
            "damage_quota",
            "none",
        }

    def test_outcome_is_frozen(self) -> None:
        outcome, _ = _admit()
        with pytest.raises(FrozenInstanceError):
            outcome.admitted = not outcome.admitted  # type: ignore[misc]

    def test_nothing_in_the_payload_has_a_secret_classified_name(self, tmp_path: Path) -> None:
        """Wrapping check: payload keys are safe names for a persisted row."""
        outcome, _ = _admit()
        for key in outcome.to_dict():
            assert isinstance(key, str)
            assert key.isidentifier(), key

    def test_admit_refuses_a_zero_duration_before_any_stage(self) -> None:
        """A zero-duration mutation is not a mutation: refused before any stage."""
        with pytest.raises(ProviderParticipationError):
            admit_cloud_action(
                AwsCloudAdapter(_CountingTransport(), rate_cards=_rates()),
                _action(),
                CloudRoleRef(
                    role_id="declared.operator",
                    provider=CloudProviderRef(provider=CloudProvider.AWS),
                    granted=GRAANTS_ALL,
                ),
                run_id="run-1",
                owner_agent="agent",
                duration_s=0.0,
                ceiling=1.0,
                quota=DamageQuota(),
                ledger=DamageLedger(),
            )
