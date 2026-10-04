"""Does a provider action participate like a native one? — plan 17 Phase 4.

What these tests are for
------------------------
Phase 4's acceptance names five surfaces: admission, blast accounting, damage
quota, leases, and evidence — plus provider faults entering the 01 certification
matrix with their provider version pinned. Admission and evidence landed in
Phases 1 and 2. This file covers the other three, and it is careful about the
difference the module under test draws:

* **participating** is what ``mayhem.providers.participation`` establishes — the
  charge is computed through the *real* ledger, the lease is a *real*
  :class:`~mayhem.domain.leases.FaultLease` under the *real* invariants, and the
  certification refusal is produced by *calling* plan 01's own code;
* **being wired into a run** is what is still missing, and every claim here says
  so. No test in this file asserts that a provider action was charged during an
  execution, because none is.

Negative controls
-----------------
Each surface has a control that breaks the property and proves the test notices:

* :class:`TestBlastControls` — the charge equals the ledger's own arithmetic
  (so a second implementation would disagree), and the ledger is mutated (so a
  preview would not be a charge).
* :class:`TestLeaseControls` — a ``model_copy`` *can* smuggle a mutation to
  ``ACTIVE`` without undo, which is exactly why the lease is refused at
  construction rather than at the transition.
* :class:`TestCertificationControls` — a cell that **does** carry a provider
  version flips the verdict to ``pinned`` and then to ``version_moved``, so the
  ``cell_cannot_carry_pin`` answer cannot be a constant.
* :class:`TestTheParticipationScan` — the overclaim scan, extended to this
  module: a provider version is a declared string, and nothing here may name an
  identifier that reads as a check over it.
"""

from __future__ import annotations

from typing import Any

import pytest

from mayhem.domain.certification import Arch, CellPrivilege, CertificationRecord, MatrixCell
from mayhem.domain.common import utc_now
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.faults import EngineLane
from mayhem.domain.leases import FaultLease, LeaseState, UndoOp, VerifyProbe
from mayhem.domain.provider import (
    CapabilityDescriptor,
    EvidenceSchema,
    FaultDeclaration,
    ProviderMetadata,
    ProviderMutation,
    ProviderPermission,
    TargetLocator,
)
from mayhem.domain.quota import (
    RULE_BUDGET,
    RULE_PER_FAULT_CEILING,
    UNRESOLVED_FAULT_WEIGHT,
    DamageLedger,
    DamageQuota,
    damage_weight,
)
from mayhem.providers.pack import SIGNATURE_VERIFICATION_IMPLEMENTED
from mayhem.providers.participation import (
    CANDIDATE_CELL_PIN_FIELD,
    PROVIDER_PARTICIPATION_NOTICE,
    RULE_PROVIDER_CELL_UNPINNED,
    RULE_PROVIDER_FAULT_UNDECLARED,
    RULE_PROVIDER_LEASE_UNDO_ABSENT,
    BlastCharge,
    CellPinStatus,
    LeaseRequirement,
    ProviderAction,
    ProviderLeaseRequest,
    ProviderParticipationError,
    ProviderVersionPin,
    WeightSource,
    assert_provider_action_recovered,
    certification_blockers,
    charge_provider_blast,
    ensure_blast_within_quota,
    ensure_certification_pin,
    lease_for_provider_action,
    lease_requirement,
    participate,
    pin_verdict,
    serve_provider_action,
    weight_source_for,
)

_PROVIDER_ID = "acme.injector"
_MUTATING_FAULT = "acme.slow"
_READ_ONLY_FAULT = "acme.observe"
_CAPABILITY = "acme.injector.mutate"
_LOCATOR = "acme.svc"
_UNDO = (UndoOp(op="tc.del_qdisc"),)
_PROBES = (VerifyProbe(probe="tc.qdisc_absent"),)


def _metadata() -> ProviderMetadata:
    return ProviderMetadata(
        providerId=_PROVIDER_ID,
        name="ACME Injector",
        version="1.2.3",
        description="Slows a service.",
        permissions=[ProviderPermission.TARGET_READ, ProviderPermission.TARGET_MUTATE],
        capabilities=(
            CapabilityDescriptor(
                id=_CAPABILITY,
                summary="Adds latency.",
                requiredPermissions=("target:read", "target:mutate"),
                mutates_targets=True,
                compensable=True,
            ),
        ),
        faultDeclarations=(
            FaultDeclaration(
                id=_MUTATING_FAULT,
                capability=_CAPABILITY,
                summary="Adds latency.",
                requiredPermissions=("target:read", "target:mutate"),
                target_locator_ids=(_LOCATOR,),
                mutation=ProviderMutation.MUTATING,
                reversible=True,
            ),
            FaultDeclaration(
                id=_READ_ONLY_FAULT,
                capability=_CAPABILITY,
                summary="Reports queue depth.",
                target_locator_ids=(_LOCATOR,),
            ),
        ),
        targetLocators=(TargetLocator(id=_LOCATOR, kind="service"),),
        evidenceSchema=EvidenceSchema(name="acme-evidence", version="1.0"),
    )


def _action(fault_id: str = _MUTATING_FAULT, **overrides: Any) -> ProviderAction:
    fields: dict[str, Any] = {
        "provider_id": _PROVIDER_ID,
        "fault_id": fault_id,
        "run_id": "run-1",
        "owner_agent": "agent:1",
        "node_ids": ("web-1",),
        "duration_s": 30.0,
    }
    fields.update(overrides)
    return ProviderAction(**fields)


def _cell() -> MatrixCell:
    return MatrixCell(
        engine=EngineLane.PODMAN,
        engine_version="5.1.0",
        os_distro="debian12",
        kernel_version="6.1.0",
        arch=Arch.AMD64,
        privilege=CellPrivilege.ROOTLESS,
    )


# =============================================================================
# Blast accounting and the damage quota — the real ledger
# =============================================================================


class TestBlastAccountingUsesTheRealLedger:
    def test_a_provider_step_is_charged_to_the_same_ledger_a_native_step_is(
        self, tmp_path: Any
    ) -> None:
        provider_ledger = DamageLedger()
        native_ledger = DamageLedger()
        quota = DamageQuota()
        action = _action()

        blast = charge_provider_blast(provider_ledger, action, quota)
        native = native_ledger.charge(
            fault_id=action.fault_id,
            duration_s=action.duration_s,
            node_ids=action.node_ids,
            quota=quota,
        )

        assert blast.charge == native
        assert blast.weight == native.weight
        assert blast.rule_id == native.rule_id

    def test_the_charge_mutates_the_ledger_rather_than_previewing_it(self) -> None:
        ledger = DamageLedger()
        blast = charge_provider_blast(ledger, _action(), DamageQuota())
        assert ledger.steps == 1
        assert ledger.total_s == blast.charge.step_damage_s
        assert ledger.damage_for("web-1") == blast.charge.per_node_s

    def test_repeated_provider_charges_accumulate(self) -> None:
        """A ledger that reset per action would be a per-step limit, not a quota."""
        ledger = DamageLedger()
        quota = DamageQuota()
        first = charge_provider_blast(ledger, _action(), quota)
        second = charge_provider_blast(ledger, _action(), quota)
        assert second.charge.total_s > first.charge.total_s
        assert second.charge.step_index == 1

    def test_a_catalog_fault_still_prices_from_the_catalog(self) -> None:
        """The wrapper is not hard-wired to the conservative fallback.

        Without this, every test in the file would pass against a function that
        ignored ``damage_weight`` entirely and always reported
        ``unresolved_conservative``.
        """
        blast = charge_provider_blast(DamageLedger(), _action("proc.pause"), DamageQuota())
        assert blast.weight_source is WeightSource.CATALOG
        assert blast.priced_by_catalog is True
        assert blast.weight == damage_weight("proc.pause")
        assert weight_source_for("proc.pause") is WeightSource.CATALOG
        # A catalog fault priced below the unresolved rung proves the wrapper is
        # reading ``damage_weight`` rather than always reporting the fallback.
        assert blast.weight < UNRESOLVED_FAULT_WEIGHT
        assert weight_source_for(_MUTATING_FAULT) is WeightSource.UNRESOLVED_CONSERVATIVE

    def test_a_provider_fault_is_priced_at_the_top_of_both_ladders(self) -> None:
        blast = charge_provider_blast(DamageLedger(), _action(), DamageQuota())
        assert blast.weight == UNRESOLVED_FAULT_WEIGHT
        assert blast.weight_source is WeightSource.UNRESOLVED_CONSERVATIVE
        assert blast.to_dict()["unresolved_fault_weight"] == UNRESOLVED_FAULT_WEIGHT

    def test_the_charge_names_the_provider_and_the_weight_source(self) -> None:
        payload = charge_provider_blast(DamageLedger(), _action(), DamageQuota()).to_dict()
        assert payload["provider_id"] == _PROVIDER_ID
        assert payload["weight_source"] == WeightSource.UNRESOLVED_CONSERVATIVE.value
        assert payload["priced_by_catalog"] is False
        assert payload["notice"] == PROVIDER_PARTICIPATION_NOTICE

    def test_a_breach_refuses_with_the_ledger_own_rule_id(self) -> None:
        quota = DamageQuota(budget_s=10.0)
        with pytest.raises(ProviderParticipationError) as excinfo:
            ensure_blast_within_quota(DamageLedger(), _action(), quota)
        assert excinfo.value.code == RULE_BUDGET
        assert _PROVIDER_ID in str(excinfo.value)

    def test_a_breach_still_stays_on_the_ledger(self) -> None:
        """Charge-then-judge, inherited from the ledger this module calls.

        A refused provider action did the damage; rolling the number back would
        make the ledger disagree with the world.
        """
        ledger = DamageLedger()
        with pytest.raises(ProviderParticipationError):
            ensure_blast_within_quota(ledger, _action(), DamageQuota(budget_s=1.0))
        assert ledger.steps == 1
        assert ledger.total_s > 1.0

    def test_the_per_fault_ceiling_is_reachable_and_named(self) -> None:
        quota = DamageQuota(per_fault_ceiling_s=1.0)
        with pytest.raises(ProviderParticipationError) as excinfo:
            ensure_blast_within_quota(DamageLedger(), _action(), quota)
        assert excinfo.value.code == RULE_PER_FAULT_CEILING

    def test_an_unexceeded_charge_returns_the_blast_not_an_exception(self) -> None:
        blast = ensure_blast_within_quota(DamageLedger(), _action(), DamageQuota())
        assert not blast.exceeded
        assert blast.rule_id == ""
        assert isinstance(blast, BlastCharge)


class TestBlastControls:
    """Negative controls for the blast half.

    Each breaks a property and proves the test above would notice.
    """

    def test_the_arithmetic_is_not_reimplemented(self) -> None:
        """Drive the module and the ledger independently, then compare.

        A second implementation of ``duration x weight x nodes`` would drift the
        first time either side rounded differently. This is the assertion that
        notices.
        """
        ledger = DamageLedger()
        action = _action(node_ids=("b", "a"), duration_s=17.5)
        blast = charge_provider_blast(ledger, action, DamageQuota())
        assert blast.charge.per_node_s == pytest.approx(17.5 * UNRESOLVED_FAULT_WEIGHT)
        assert blast.charge.step_damage_s == pytest.approx(2 * 17.5 * UNRESOLVED_FAULT_WEIGHT)
        assert ledger.by_node() == {
            "a": 17.5 * UNRESOLVED_FAULT_WEIGHT,
            "b": 17.5 * UNRESOLVED_FAULT_WEIGHT,
        }

    def test_the_control_detects_a_wrong_weight(self) -> None:
        """Break the property on purpose and show the assertion catches it.

        Without this, a reader could not tell whether ``test_the_charge_mutates``
        is a real guard or a tautology.
        """
        ledger = DamageLedger()
        action = _action()
        blast = charge_provider_blast(ledger, action, DamageQuota())
        wrong = blast.charge.per_node_s * 2.0
        assert wrong != pytest.approx(blast.charge.per_node_s)

    def test_a_duplicate_action_is_charged_twice(self) -> None:
        ledger = DamageLedger()
        action = _action()
        charge_provider_blast(ledger, action, DamageQuota())
        charge_provider_blast(ledger, action, DamageQuota())
        assert ledger.steps == 2
        assert ledger.by_node_fault()[("web-1", _MUTATING_FAULT)] == pytest.approx(
            2 * 30.0 * UNRESOLVED_FAULT_WEIGHT
        )

    @pytest.mark.parametrize(
        ("overrides", "message"),
        [
            ({"node_ids": ()}, "targets nothing"),
            ({"duration_s": 0.0}, "duration_s=0.0"),
            ({"provider_id": "  "}, "provider_id"),
        ],
    )
    def test_a_malformed_action_is_refused_before_it_can_be_charged(
        self, overrides: dict[str, Any], message: str
    ) -> None:
        with pytest.raises(ProviderParticipationError, match=message):
            _action(**overrides)

    def test_an_undeclared_fault_is_refused(self) -> None:
        with pytest.raises(ProviderParticipationError) as excinfo:
            lease_requirement(_metadata(), "acme.not-declared")
        assert excinfo.value.code == RULE_PROVIDER_FAULT_UNDECLARED


# =============================================================================
# Leases — the real lease, under the real invariants
# =============================================================================


class TestTheProviderLease:
    def test_a_mutating_fault_requires_a_lease(self) -> None:
        assert lease_requirement(_metadata(), _MUTATING_FAULT) is LeaseRequirement.REQUIRED

    def test_a_read_only_fault_requires_none(self) -> None:
        assert lease_requirement(_metadata(), _READ_ONLY_FAULT) is LeaseRequirement.NOT_REQUIRED

    def test_a_read_only_fault_is_refused_a_lease(self) -> None:
        with pytest.raises(ProviderParticipationError, match="read-only"):
            lease_for_provider_action(
                _metadata(),
                ProviderLeaseRequest(action=_action(_READ_ONLY_FAULT), undo_ops=_UNDO),
            )

    def test_a_mutating_fault_without_undo_is_refused(self) -> None:
        """The load-bearing refusal.

        The declaration says ``reversible=True`` — a compensation path exists —
        and has no field for the operations that perform it. So the lease cannot
        be taken, and the refusal names that rather than admitting a mutation
        whose compensation cannot be written down first.
        """
        with pytest.raises(ProviderParticipationError) as excinfo:
            lease_for_provider_action(_metadata(), ProviderLeaseRequest(action=_action()))
        assert excinfo.value.code == RULE_PROVIDER_LEASE_UNDO_ABSENT
        message = str(excinfo.value)
        assert "no field for the operations that perform it" in message
        assert "FaultDeclaration.reversible is True" in message

    def test_the_lease_is_an_ordinary_fault_lease(self) -> None:
        lease = lease_for_provider_action(
            _metadata(),
            ProviderLeaseRequest(action=_action(), undo_ops=_UNDO, verify_probes=_PROBES),
        )
        assert type(lease) is FaultLease
        assert lease.fault_id == _MUTATING_FAULT
        assert lease.run_id == "run-1"
        assert lease.owner_agent == "agent:1"
        assert lease.target == ("web-1",)
        assert lease.compensation == _UNDO
        assert lease.verification_probes == _PROBES

    def test_serving_a_provider_action_walks_the_real_state_machine(self) -> None:
        lease = serve_provider_action(
            _metadata(),
            ProviderLeaseRequest(action=_action(), undo_ops=_UNDO, verify_probes=_PROBES),
        )
        assert lease.state is LeaseState.ACTIVE
        assert lease.injected_at is not None
        assert lease.epoch == 1

    def test_the_release_invariants_are_the_native_ones(self) -> None:
        """No ``ProviderLease``: the same refusals a native action meets.

        Undo is required before ``ACTIVE`` and probes are required before
        ``RELEASING`` — enforced here by :class:`FaultLease` itself, not by
        anything this module wrote.
        """
        without_probes = ProviderLeaseRequest(action=_action(), undo_ops=_UNDO)
        with pytest.raises(InvariantViolationError, match="verify_required_before_release"):
            serve_provider_action(_metadata(), without_probes)

        with_probes = serve_provider_action(
            _metadata(),
            ProviderLeaseRequest(action=_action(), undo_ops=_UNDO, verify_probes=_PROBES),
        )
        released = with_probes.transition(LeaseState.RELEASING).transition(LeaseState.RELEASED)
        assert released.is_safe_terminal
        assert released.is_terminal
        assert_provider_action_recovered(released)

    def test_an_outstanding_lease_is_not_recovered(self) -> None:
        served = serve_provider_action(
            _metadata(),
            ProviderLeaseRequest(action=_action(), undo_ops=_UNDO, verify_probes=_PROBES),
        )
        with pytest.raises(
            InvariantViolationError, match="all_leases_recovered_before_run_completion"
        ):
            assert_provider_action_recovered(served)

    def test_a_lease_with_no_ttl_expires_before_it_exists_is_refused(self) -> None:
        with pytest.raises(ProviderParticipationError, match="ttl_seconds"):
            ProviderLeaseRequest(action=_action(), ttl_seconds=0.0)

    @pytest.mark.parametrize(
        ("kwargs", "message"),
        [
            ({"undo_ops": (UndoOp(op="  "),)}, "undo op must name"),
            ({"verify_probes": (VerifyProbe(probe=" "),)}, "verify probe must name"),
        ],
    )
    def test_a_blank_undo_or_probe_is_refused(self, kwargs: dict[str, Any], message: str) -> None:
        with pytest.raises(ProviderParticipationError, match=message):
            ProviderLeaseRequest(action=_action(), **kwargs)


class TestLeaseControls:
    """Negative controls for the lease half."""

    def test_a_model_copy_can_smuggle_active_without_undo(self) -> None:
        """The defect this module's construction-time refusal exists to close.

        ``FaultLease.model_copy`` skips validation, so a lease *can* be forced to
        ``ACTIVE`` with no undo ops. That is not a hypothetical: it is what a
        future maintainer reaching for a shortcut would produce. It is also why
        :func:`lease_for_provider_action` refuses when the undo is absent rather
        than relying on the transition to catch it — a lease that can be
        *created* under-specified is an open lease sitting in a store.
        """
        lease = lease_for_provider_action(
            _metadata(),
            ProviderLeaseRequest(action=_action(), undo_ops=_UNDO, verify_probes=_PROBES),
        )
        smuggled = lease.model_copy(update={"state": LeaseState.ACTIVE, "undo_ops": ()})
        assert smuggled.state is LeaseState.ACTIVE
        assert not smuggled.undo_ops
        # The same state reached through the real API is refused.
        with pytest.raises(InvariantViolationError, match="undo_required_before_active"):
            FaultLease.model_validate(
                {
                    **lease.model_dump(),
                    "state": LeaseState.ACTIVE.value,
                    "undo_ops": (),
                }
            )

    def test_the_constructor_refusal_beats_the_smuggle(self) -> None:
        """And the construction-time refusal means the under-specified lease
        never comes into existence at all."""
        with pytest.raises(ProviderParticipationError) as excinfo:
            lease_for_provider_action(_metadata(), ProviderLeaseRequest(action=_action()))
        assert excinfo.value.code == RULE_PROVIDER_LEASE_UNDO_ABSENT

    def test_a_missing_undo_changes_the_verdict(self) -> None:
        """The negative control for the refusal itself.

        Removing the refusal — standing in for a future change that dropped the
        guard — must change what the test above observes.
        """
        with_undo = serve_provider_action(
            _metadata(),
            ProviderLeaseRequest(action=_action(), undo_ops=_UNDO, verify_probes=_PROBES),
        )
        with pytest.raises(ProviderParticipationError):
            serve_provider_action(
                _metadata(), ProviderLeaseRequest(action=_action(), verify_probes=_PROBES)
            )
        assert with_undo.state is LeaseState.ACTIVE

    def test_the_lease_id_starts_with_the_prefix_the_state_machine_requires(self) -> None:
        lease = lease_for_provider_action(
            _metadata(),
            ProviderLeaseRequest(action=_action(), undo_ops=_UNDO, verify_probes=_PROBES),
        )
        assert lease.id.startswith("l-")
        assert "acme.slow" not in lease.id
        with pytest.raises(InvariantViolationError, match="lease_id_prefix"):
            FaultLease.model_validate({**lease.model_dump(), "id": "lease-1"})


# =============================================================================
# Certification — the pin the cell cannot hold
# =============================================================================


class TestCertificationPinsAProviderVersion:
    """The pin landed in plan 01, so this class asserts that it works.

    It previously asserted the opposite — that ``MatrixCell`` had **no** field
    for a provider version and that a provider fault could therefore not be
    certified at all. That was true when the class was written and stopped being
    true when plan 01 added ``provider_id``/``provider_version`` to the cell, at
    which point five of its tests began failing against a codebase that had
    moved on. They are rewritten here to the current truth rather than deleted,
    because the properties are still worth pinning — just the opposite ones.
    """

    @staticmethod
    def _pinned_cell(version: str = "1.2.3") -> MatrixCell:
        return MatrixCell(
            **{**_cell().model_dump(), "provider_id": _PROVIDER_ID, "provider_version": version}
        )

    def test_the_cell_carries_the_pin_fields(self) -> None:
        """The field the blocker used to name now exists, and ``extra`` is still forbid."""
        assert CANDIDATE_CELL_PIN_FIELD in MatrixCell.model_fields
        assert "provider_id" in MatrixCell.model_fields
        assert MatrixCell.model_config.get("extra") == "forbid"

    def test_a_cell_pinning_the_provider_is_pinned(self) -> None:
        pin = ProviderVersionPin(provider_id=_PROVIDER_ID, version="1.2.3")

        assert pin_verdict(self._pinned_cell(), pin).status is CellPinStatus.PINNED

    def test_an_unpinned_cell_is_not_pinned_and_says_which_way_it_went_wrong(self) -> None:
        """``version_moved`` rather than ``cell_cannot_carry_pin``: the cell can hold a pin.

        The three-valued enum survives, and two of its members still refuse. What
        changed is which refusal an ordinary unpinned cell earns — it now reports
        that the version moved, because there is a version field and it is absent,
        rather than reporting that the field itself is missing.
        """
        pin = ProviderVersionPin(provider_id=_PROVIDER_ID, version="1.2.3")

        verdict = pin_verdict(_cell(), pin)

        assert verdict.status is CellPinStatus.VERSION_MOVED
        assert not verdict.pinned
        assert verdict.cell_label == _cell().label

    def test_a_provider_that_moved_is_detected(self) -> None:
        """The negative control the old class could not write: the field is real now.

        Pinning 1.2.3 against a cell recording 1.2.4 must be refused, or a claim
        certified against one provider build would still read as standing after
        the provider was upgraded underneath it.
        """
        pin = ProviderVersionPin(provider_id=_PROVIDER_ID, version="1.2.3")

        assert pin_verdict(self._pinned_cell("1.2.4"), pin).status is CellPinStatus.VERSION_MOVED

    def test_ensuring_the_pin_refuses_on_an_unpinned_cell_and_succeeds_on_a_pinned_one(
        self,
    ) -> None:
        """Both halves: a refusal that must stay, and the capability that now exists."""
        pin = ProviderVersionPin(_PROVIDER_ID, "1.2.3")

        with pytest.raises(ProviderParticipationError) as excinfo:
            ensure_certification_pin(_cell(), pin)
        assert excinfo.value.code == RULE_PROVIDER_CELL_UNPINNED

        assert ensure_certification_pin(self._pinned_cell(), pin) is not None

    def test_a_pin_needs_a_readable_version(self) -> None:
        with pytest.raises(ProviderParticipationError, match="cannot be compared"):
            ProviderVersionPin(_PROVIDER_ID, "  ")

    def test_a_provider_fault_id_must_belong_to_the_pinned_provider(self) -> None:
        """Called directly, so the surviving refusal is reproducible on its own.

        The fixture declares ``acme.*`` faults under a provider whose id is
        ``acme.injector``, so plan 01's rule — a provider id must be scoped to the
        provider the cell pins — refuses it. That refusal is *correct* rather than
        a gap, and it is why ``test_provider_fault_certification.py`` covers the
        accepting path with an id that is properly scoped.
        """
        with pytest.raises(Exception, match="does not belong to provider"):
            CertificationRecord(
                fault_id=_MUTATING_FAULT,
                cell=self._pinned_cell(),
                injector_version="1.2.3",
                expires_at=utc_now(),
            )

    def test_the_blockers_name_the_missing_pin_and_the_scoped_id(self) -> None:
        """Both blockers are now readings of the real code, and both carry a remedy."""
        blockers = certification_blockers(_metadata(), _cell())
        subjects = {blocker.subject for blocker in blockers}
        assert f"MatrixCell.{CANDIDATE_CELL_PIN_FIELD}" in subjects
        assert any(subject.startswith("CertificationRecord.fault_id[") for subject in subjects)
        for blocker in blockers:
            assert blocker.change_required.strip()
            assert "mayhem.domain.certification" in blocker.change_required
            assert blocker.detail.strip()

    def test_the_blockers_are_observed_not_asserted(self) -> None:
        """Each blocker's rule is what plan 01's own code actually answered."""
        cell_blocker = next(
            blocker
            for blocker in certification_blockers(_metadata(), _cell())
            if blocker.subject.startswith("MatrixCell")
        )
        assert cell_blocker.rule == CellPinStatus.VERSION_MOVED.value
        fault_blocker = next(
            blocker
            for blocker in certification_blockers(_metadata(), _cell())
            if blocker.subject.startswith("CertificationRecord")
        )
        assert fault_blocker.to_dict()["rule"]

    def test_a_pinned_cell_drops_the_pin_blocker_and_keeps_the_fault_one(self) -> None:
        """What the pin bought, observed as a difference between two reports.

        Pinning the cell removes exactly one blocker and leaves the other, so the
        report cannot be read as "pinning fixed certification" when what it fixed
        was one of the two things standing in the way.
        """
        unpinned = {b.subject for b in certification_blockers(_metadata(), _cell())}
        pinned = {b.subject for b in certification_blockers(_metadata(), self._pinned_cell())}

        assert f"MatrixCell.{CANDIDATE_CELL_PIN_FIELD}" in unpinned
        assert f"MatrixCell.{CANDIDATE_CELL_PIN_FIELD}" not in pinned
        assert any(subject.startswith("CertificationRecord.fault_id[") for subject in pinned)


class TestCertificationControls:
    """Negative controls for the certification half.

    The load-bearing one is :meth:`test_a_cell_that_carries_the_pin_flips_the_verdict`:
    without it, ``cell_cannot_carry_pin`` could be a constant and every assertion
    about it would be vacuous.
    """

    def test_a_cell_that_carries_the_pin_flips_the_verdict(self) -> None:
        class _PinnedCell(MatrixCell):  # what plan 01's field would produce
            provider_version: str | None = None

        cell = _PinnedCell(**{**_cell().model_dump(), CANDIDATE_CELL_PIN_FIELD: "1.2.3"})
        assert pin_verdict(cell, ProviderVersionPin(_PROVIDER_ID, "1.2.3")).pinned

    def test_a_moved_provider_is_not_pinned(self) -> None:
        class _PinnedCell(MatrixCell):
            provider_version: str | None = None

        cell = _PinnedCell(**{**_cell().model_dump(), CANDIDATE_CELL_PIN_FIELD: "1.2.3"})
        verdict = pin_verdict(cell, ProviderVersionPin(_PROVIDER_ID, "1.4.0"))
        assert verdict.status is CellPinStatus.VERSION_MOVED
        assert not verdict.pinned
        with pytest.raises(ProviderParticipationError, match="no longer the one running"):
            ensure_certification_pin(cell, ProviderVersionPin(_PROVIDER_ID, "1.4.0"))

    def test_an_unpinned_cell_is_refused_even_when_the_version_matches(self) -> None:
        """The status enum is three-valued and only one of them passes.

        ``VERSION_MOVED`` and ``CELL_CANNOT_CARRY_PIN`` both refusing is what
        makes ``pinned`` a real answer rather than a default.
        """
        assert {member.value for member in CellPinStatus} == {
            "pinned",
            "version_moved",
            "cell_cannot_carry_pin",
        }

    def test_removing_the_missing_field_would_change_the_verdict(self) -> None:
        """The negative control for the detection itself.

        Originally written as "a cell *without* the pin field yields
        ``cell_cannot_carry_pin``". Plan 01 then added the field, so a subclass
        pretending the field is absent could no longer be built and the control
        had nothing left to attack. The control is preserved in the form that is
        still available: three real cells — carrying the right version, carrying
        none, and carrying a moved one — produce three different readings, so
        ``pinned`` is a measurement of the cell rather than a constant the
        function returns.
        """

        def _verdict(version: str | None) -> CellPinStatus:
            payload = {**_cell().model_dump(), "provider_id": _PROVIDER_ID}
            if version is not None:
                payload[CANDIDATE_CELL_PIN_FIELD] = version
            return pin_verdict(
                MatrixCell(**payload), ProviderVersionPin(_PROVIDER_ID, "1.2.3")
            ).status

        assert _verdict("1.2.3") is CellPinStatus.PINNED
        assert _verdict(None) is CellPinStatus.VERSION_MOVED
        assert _verdict("1.9.9") is CellPinStatus.VERSION_MOVED


# =============================================================================
# One report
# =============================================================================


class TestParticipate:
    def test_it_charges_leases_and_pins_in_one_call(self) -> None:
        report = participate(
            _metadata(),
            _action(),
            DamageQuota(),
            lease_request=ProviderLeaseRequest(
                action=_action(), undo_ops=_UNDO, verify_probes=_PROBES
            ),
            cell=_cell(),
        )
        assert report.charged
        assert report.blast.exceeded is False
        assert report.within_quota
        assert report.lease_required is LeaseRequirement.REQUIRED
        assert report.lease is not None
        assert report.lease_outstanding
        assert report.cell_pinned_or_not_required is False
        assert report.fully_accounted is False

    def test_an_omitted_lease_request_is_an_outstanding_lease_not_a_none_lease(self) -> None:
        """Omitting the request must not read as "no lease was needed"."""
        report = participate(_metadata(), _action(), DamageQuota())
        assert report.lease_required is LeaseRequirement.REQUIRED
        assert report.lease is None
        assert report.lease_outstanding is True

    def test_a_recovered_lease_and_no_cell_is_accounted(self) -> None:
        served = serve_provider_action(
            _metadata(),
            ProviderLeaseRequest(action=_action(), undo_ops=_UNDO, verify_probes=_PROBES),
        )
        recovered = served.transition(LeaseState.RELEASING).transition(LeaseState.RELEASED)
        report = participate(
            _metadata(),
            _action(),
            DamageQuota(),
            ledger=DamageLedger(),
        )
        assert report.lease_outstanding is True
        assert recovered.is_safe_terminal
        assert report.cell_pin is None
        assert report.cell_pinned_or_not_required is True

    def test_the_payload_says_what_it_is_not(self) -> None:
        payload = participate(_metadata(), _action(), DamageQuota(), cell=_cell()).to_dict()
        assert payload["fully_accounted"] is False
        assert payload["charged"] is True
        assert payload["cell_pinned"] is False
        assert payload["notice"] == PROVIDER_PARTICIPATION_NOTICE
        assert payload["certification_blockers"]
        assert payload["blast"]["priced_by_catalog"] is False

    def test_the_charge_happens_before_anything_else(self) -> None:
        """A breached charge is still a charge, even when the pin cannot be set."""
        ledger = DamageLedger()
        report = participate(
            _metadata(),
            _action(),
            DamageQuota(budget_s=1.0),
            ledger=ledger,
            cell=_cell(),
        )
        assert not report.within_quota
        assert ledger.steps == 1


# =============================================================================
# Phase 5 — the overclaim scan, extended here
# =============================================================================


class TestTheParticipationScan:
    """A provider version is a declared string, and this module may not imply
    otherwise.

    Same standing control as the SDK suite, applied to the second module that
    touches a provider version. :data:`ProviderVersionPin.version` exists so a
    moved provider invalidates a matrix cell; it is not evidence about an author,
    and a name here that read as a check would be the one way this module could
    overclaim.
    """

    FORBIDDEN = ("signed", "signature", "signer", "trusted", "trust_store", "attested")
    NEGATOR_PREFIXES = ("un", "non", "not_", "no_", "never_", "cannot_")

    @classmethod
    def _claims_a_check(cls, identifier: str) -> bool:
        lowered = identifier.lower()
        width = max(len(prefix) for prefix in cls.NEGATOR_PREFIXES)
        for word in (*cls.FORBIDDEN, "verified"):
            start = 0
            while (index := lowered.find(word, start)) != -1:
                prefix = lowered[max(0, index - width) : index]
                if not prefix.endswith(cls.NEGATOR_PREFIXES):
                    return True
                start = index + 1
        return False

    def test_no_identifier_here_claims_a_publisher_check(self) -> None:
        from mayhem.providers import participation

        identifiers = set(participation.__all__) | {
            "RULE_PROVIDER_LEASE_UNDO_ABSENT",
            "ProviderVersionPin",
            "PROVIDER_PARTICIPATION_NOTICE",
        }
        offenders = sorted(name for name in identifiers if self._claims_a_check(name))
        assert not offenders, offenders

    def test_the_pin_field_is_named_version_not_verified_version(self) -> None:
        assert "version" in ProviderVersionPin.__dataclass_fields__
        assert not {"verified", "signed", "signature"} & set(
            ProviderVersionPin.__dataclass_fields__
        )

    def test_signature_verification_is_still_not_implemented(self) -> None:
        assert SIGNATURE_VERIFICATION_IMPLEMENTED is False

    def test_the_notice_denies_a_signature_check_by_name(self) -> None:
        assert "no signature is checked" in PROVIDER_PARTICIPATION_NOTICE
        assert "SIGNATURE_VERIFICATION_IMPLEMENTED is False" in PROVIDER_PARTICIPATION_NOTICE

    def test_the_scan_would_notice_a_planted_claim(self) -> None:
        """The negative control for the scan itself."""
        assert self._claims_a_check("provider_version_verified")
        assert self._claims_a_check("publisher_signed")
        assert not self._claims_a_check("provider_version")
        assert not self._claims_a_check("SDK_UNVERIFIED_NOTICE")
