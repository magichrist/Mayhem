"""Certification records: every state transition, pinned, plus the negative control.

Why this file exists
--------------------
``verified-live`` is only a claim if the thing that backs it can go away again.
A badge that survives the deletion of its evidence is decoration. So the tests
here are written as two groups:

* **the transitions.** ``pending → certified → expiring → stale``, plus
  ``failed`` and the terminal ``incompatible`` side state, each entered only
  through the pure predicate that is supposed to enter it, and refused
  everywhere else. Every predicate takes ``now`` / the current cell as an
  argument, so a policy can be replayed rather than waited for.
* **the consequences.** The promotion engine must stop reporting a live rung
  the moment a record stops granting one — expired, invalidated by a kernel
  bump, or deleted outright.

The negative controls close the obvious forgeries: a ``certified`` record with
no evidence, a bundle whose hash is not a sha256, a bundle that omits the digest
for a claim it is cited for, and a state that does not say why. Each is refused
at *construction*, so none of them can exist to be reported on.

The last test re-states the domain law locally: this module may not import the
toolkit, agents, controller, infra, or the IO modules. ``pyproject.toml``'s
import-linter contract enforces the same thing in CI, but that check needs an
extra dependency, so the guard also lives here.
"""

from __future__ import annotations

import ast
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from pydantic import ValidationError

import mayhem.domain.certification as certification_module
from mayhem.domain.capabilities import Capability
from mayhem.domain.catalog import definition_for
from mayhem.domain.certification import (
    DEFAULT_CERTIFICATION_TTL,
    DEFAULT_EXPIRY_WARNING,
    LEGAL_TRANSITIONS,
    REQUIRED_EVIDENCE_DIGESTS,
    Arch,
    CellPrivilege,
    CertificationRecord,
    CertificationState,
    CertificationTransitionError,
    EvidenceBundleRef,
    MatrixCell,
    certified_engines,
    certify,
    expire_by_time,
    invalidate_on_change,
    mark_failed,
    mark_incompatible,
)
from mayhem.domain.faults import EngineLane, MaturityLevel
from mayhem.infra.promotion import (
    CERTIFICATION_RECORDED,
    MATURITY_MEANING,
    REQUIRED_BUNDLE_DIGESTS,
    REQUIRED_LIVE_ENGINES,
    BundleRef,
    CatalogProbe,
    EvidenceStore,
    LiveRunRecord,
    Observation,
    PromotionDecision,
    build_probe,
    evaluate_maturity,
)

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

FAULT_ID = "proc.pause"
_NOW = datetime(2026, 3, 1, 12, 0, tzinfo=UTC)
#: A short validity window, so ``_INSIDE_WINDOW`` really is inside the warning
#: window and ``_AFTER`` really is past the deadline.
_TTL = timedelta(days=10)
_INSIDE_WINDOW = _NOW + timedelta(days=5)
_AFTER = _NOW + timedelta(days=20)
_HASH = "a" * 64
_DIGEST = "b" * 64


# ── builders ────────────────────────────────────────────────────────────────


def _cell(
    *,
    engine: EngineLane = EngineLane.DOCKER,
    engine_version: str = "24.0.7",
    os_distro: str = "ubuntu-24.04",
    kernel_version: str = "6.11.0-13-generic",
    arch: Arch = Arch.AMD64,
    privilege: CellPrivilege = CellPrivilege.ROOTLESS,
    capabilities: frozenset[Capability] = frozenset({Capability.NET_ADMIN}),
) -> MatrixCell:
    return MatrixCell(
        engine=engine,
        engine_version=engine_version,
        os_distro=os_distro,
        kernel_version=kernel_version,
        arch=arch,
        privilege=privilege,
        capabilities=capabilities,
    )


def _bundle(*, complete: bool = True, bundle_hash: str = _HASH) -> EvidenceBundleRef:
    digests: dict[str, str] = {}
    if complete:
        digests = dict.fromkeys(REQUIRED_EVIDENCE_DIGESTS, _DIGEST)
    return EvidenceBundleRef(
        bundle_hash=bundle_hash,
        mayhem_version="1.1.0.test",
        digests=digests,
        bundle_path="/tmp/certification/bundle.json",
    )


def _pending(
    cell: MatrixCell | None = None, *, expires_at: datetime | None = None
) -> CertificationRecord:
    return CertificationRecord(
        fault_id=FAULT_ID,
        cell=cell or _cell(),
        injector_version="tc-netem 1.9.0",
        expires_at=expires_at or (_NOW + timedelta(days=90)),
    )


def _certified(
    cell: MatrixCell | None = None,
    *,
    at: datetime = _NOW,
    ttl: timedelta = _TTL,
    bundle: EvidenceBundleRef | None = None,
) -> CertificationRecord:
    return certify(
        _pending(cell),
        at=at,
        expires_at=at + ttl,
        evidence=(bundle or _bundle(),),
        outcome="injection observed; undo restored the pre-injection baseline",
    )


def _certified_pair() -> dict[str, tuple[CertificationRecord, ...]]:
    """One certified record per required live engine."""
    return {FAULT_ID: tuple(_certified(_cell(engine=lane)) for lane in REQUIRED_LIVE_ENGINES)}


# ── the record store's shape ────────────────────────────────────────────────


def test_a_record_starts_pending_and_grants_nothing() -> None:
    record = _pending()
    assert record.state is CertificationState.PENDING
    assert record.grants_live_verification is False
    assert record.warning_window_entered is False
    assert record.evidence == ()
    assert record.label == f"{FAULT_ID}@{record.cell.label}"


def test_the_matrix_cell_names_every_dimension_a_claim_rests_on() -> None:
    cell = _cell()
    assert cell.label == ("docker@24.0.7/ubuntu-24.04/kernel-6.11.0-13-generic/amd64/rootless")
    for dimension in (
        cell.engine.value,
        cell.engine_version,
        cell.os_distro,
        cell.kernel_version,
        cell.arch.value,
        cell.privilege.value,
        Capability.NET_ADMIN.value,
    ):
        assert dimension in cell.fingerprint


def test_a_rootful_cell_is_not_the_same_claim_as_a_rootless_one() -> None:
    assert _cell(privilege=CellPrivilege.ROOT) != _cell(privilege=CellPrivilege.ROOTLESS)
    assert _cell(arch=Arch.ARM64) != _cell(arch=Arch.AMD64)


# ── pending → certified ─────────────────────────────────────────────────────


def test_certify_moves_pending_to_certified_on_complete_evidence() -> None:
    certified = _certified()
    assert certified.state is CertificationState.CERTIFIED
    assert certified.grants_live_verification is True
    assert certified.certified_at == _NOW
    assert certified.expires_at == _NOW + _TTL
    assert certified.outcome
    assert certified.reason == ""


def test_certify_defaults_the_expiry_to_the_ttl_when_none_is_given() -> None:
    certified = certify(
        _pending(),
        at=_NOW,
        evidence=(_bundle(),),
        outcome="passed on a fresh disposable cell",
    )
    assert certified.expires_at == _NOW + DEFAULT_CERTIFICATION_TTL


def test_certify_refuses_a_record_with_no_evidence_at_all() -> None:
    with pytest.raises(ValueError, match="requires at least one evidence bundle reference"):
        certify(_pending(), at=_NOW, evidence=(), outcome="looks fine to me")


def test_certify_refuses_a_bundle_that_omits_a_digest_it_is_cited_for() -> None:
    """The negative control: an incomplete bundle cannot become a claim."""
    empty = _bundle(complete=False)
    assert empty.missing_digests() == REQUIRED_EVIDENCE_DIGESTS
    with pytest.raises(ValidationError, match="does not support the claim"):
        certify(_pending(), at=_NOW, evidence=(empty,), outcome="no residues found")
    partial = EvidenceBundleRef(
        bundle_hash=_HASH,
        mayhem_version="1.1.0.test",
        digests={k: v for k, v in _bundle().digests.items() if k != "residue"},
    )
    assert partial.missing_digests() == ("residue",)
    with pytest.raises(ValidationError, match="no residue digest"):
        certify(_pending(), at=_NOW, evidence=(partial,), outcome="no residues found")


def test_a_certified_record_cannot_be_constructed_without_its_evidence() -> None:
    """Construction is the gate: there is no way to hold the badge without proof."""
    with pytest.raises(ValidationError, match="with no evidence bundle"):
        CertificationRecord.model_validate(
            {
                **_pending().model_dump(),
                "state": CertificationState.CERTIFIED,
                "outcome": "asserted, not observed",
                "certified_at": _NOW,
            }
        )


def test_a_certified_record_with_no_recorded_outcome_cannot_be_built() -> None:
    with pytest.raises(ValidationError, match="without a recorded outcome"):
        CertificationRecord.model_validate(
            {
                **_certified().model_dump(),
                "outcome": "   ",
            }
        )


def test_a_naive_expiry_is_refused() -> None:
    with pytest.raises(ValidationError, match="expires_at must be timezone-aware"):
        CertificationRecord.model_validate(
            {
                **_pending().model_dump(),
                # deliberately naive: a naive expiry must be refused at construction
                "expires_at": datetime(2026, 6, 1, 12, 0, tzinfo=UTC).replace(tzinfo=None),
            }
        )


def test_a_fabricated_bundle_hash_is_refused_when_it_is_written() -> None:
    with pytest.raises(ValidationError, match="bundle_hash must be 64 lowercase hex"):
        _bundle(bundle_hash="z" * 64)
    with pytest.raises(ValidationError, match="bundle_hash must be 64 lowercase hex"):
        _bundle(bundle_hash="A" * 64)
    with pytest.raises(ValidationError, match="digest for 'undo' must be 64 lowercase hex"):
        EvidenceBundleRef(
            bundle_hash=_HASH,
            mayhem_version="1.1.0.test",
            digests={"undo": "not-a-digest"},
        )


def test_certify_refuses_to_revive_a_record_that_is_no_longer_pending() -> None:
    for record in (_certified(), expire_by_time(_certified(ttl=timedelta(days=1)), now=_AFTER)):
        with pytest.raises(CertificationTransitionError, match="cannot move from"):
            certify(record, at=_NOW, evidence=(_bundle(),), outcome="re-asserted by hand")


def test_every_transition_out_of_a_terminal_state_is_refused() -> None:
    terminal = mark_incompatible(_certified(), reason="the kernel moved")
    assert LEGAL_TRANSITIONS[CertificationState.INCOMPATIBLE] == frozenset()
    with pytest.raises(CertificationTransitionError, match="terminal"):
        mark_failed(terminal, reason="a re-run also failed")
    with pytest.raises(CertificationTransitionError, match="terminal"):
        certify(terminal, at=_NOW, evidence=(_bundle(),), outcome="re-asserted by hand")
    # time and drift are observations, not transitions: they leave it alone
    assert expire_by_time(terminal, now=_AFTER) is terminal
    assert invalidate_on_change(terminal, cell=_cell(engine_version="25.0.0")) is terminal


# ── certified → expiring → stale ────────────────────────────────────────────


def test_a_record_inside_the_warning_window_is_expiring_but_still_counts() -> None:
    certified = _certified()
    expiring = expire_by_time(certified, now=_INSIDE_WINDOW)
    assert expiring.state is CertificationState.EXPIRING
    assert expiring.grants_live_verification is True
    assert expiring.warning_window_entered is True
    assert f"{DEFAULT_EXPIRY_WARNING.days}-day warning window" in expiring.reason
    assert certified.state is CertificationState.CERTIFIED, "the input must not be mutated"


def test_a_record_past_its_expiry_is_stale_and_counts_for_nothing() -> None:
    stale = expire_by_time(_certified(), now=_AFTER)
    assert stale.state is CertificationState.STALE
    assert stale.grants_live_verification is False
    assert "lapsed" in stale.reason


def test_expiry_wins_over_the_warning_window() -> None:
    """At the deadline the claim is already gone, not merely about to go."""
    certified = _certified()
    at_deadline = expire_by_time(certified, now=certified.expires_at)
    assert at_deadline.state is CertificationState.STALE


def test_expiring_then_stale_is_the_demotion_the_plan_names() -> None:
    certified = _certified()
    expiring = expire_by_time(certified, now=_INSIDE_WINDOW)
    stale = expire_by_time(expiring, now=_AFTER)
    assert (certified.state, expiring.state, stale.state) == (
        CertificationState.CERTIFIED,
        CertificationState.EXPIRING,
        CertificationState.STALE,
    )


def test_a_healthy_record_is_returned_untouched_by_the_clock() -> None:
    certified = _certified()
    assert expire_by_time(certified, now=_NOW + timedelta(hours=1)) is certified


def test_a_pending_record_that_ages_past_its_expiry_goes_stale() -> None:
    pending = _pending(expires_at=_NOW + timedelta(days=1))
    assert expire_by_time(pending, now=_NOW) is pending
    assert expire_by_time(pending, now=_AFTER).state is CertificationState.STALE


def test_a_stale_record_never_moves_again() -> None:
    stale = expire_by_time(_certified(), now=_AFTER)
    assert expire_by_time(stale, now=_AFTER) is stale
    assert expire_by_time(stale, now=_AFTER + timedelta(days=365)) is stale
    assert stale.grants_live_verification is False


def test_the_warning_window_is_a_policy_argument_not_a_constant() -> None:
    certified = _certified()
    # five days left: outside a two-day window, inside a six-day one.
    assert (
        expire_by_time(certified, now=_INSIDE_WINDOW, warning_window=timedelta(days=2)) is certified
    )
    assert (
        expire_by_time(certified, now=_INSIDE_WINDOW, warning_window=timedelta(days=6)).state
        is CertificationState.EXPIRING
    )


def test_the_clock_argument_must_be_timezone_aware() -> None:
    with pytest.raises(ValueError, match="now must be timezone-aware"):
        naive = datetime(2026, 3, 2, 12, 0, tzinfo=UTC).replace(tzinfo=None)
        expire_by_time(_certified(), now=naive)  # type: ignore[arg-type]


def test_an_expiry_in_the_past_is_not_backdated_by_construction() -> None:
    assert _pending(expires_at=_NOW).expires_at == _NOW


# ── failed ──────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("start", ["certified", "expiring", "stale"])
def test_mark_failed_is_reachable_from_every_non_terminal_state(start: str) -> None:
    certified = _certified()
    if start == "expiring":
        record = expire_by_time(certified, now=_INSIDE_WINDOW)
    elif start == "stale":
        record = expire_by_time(certified, now=_AFTER)
    else:
        record = certified
    failed = mark_failed(record, reason="the re-run left tc rules behind")
    assert failed.state is CertificationState.FAILED
    assert failed.grants_live_verification is False
    assert failed.reason == "the re-run left tc rules behind"


def test_mark_failed_needs_a_reason() -> None:
    with pytest.raises(ValueError, match="requires a reason"):
        mark_failed(_certified(), reason="   ")


# ── invalidation on runtime change (gap item 107) ───────────────────────────


@pytest.mark.parametrize(
    ("moved", "reason_fragment"),
    [
        ({"engine": EngineLane.PODMAN}, "the runtime cell moved"),
        ({"engine_version": "25.0.3"}, "the runtime cell moved"),
        ({"os_distro": "debian-13"}, "the runtime cell moved"),
        ({"kernel_version": "6.14.0-12-generic"}, "the runtime cell moved"),
        ({"arch": Arch.ARM64}, "the runtime cell moved"),
        ({"privilege": CellPrivilege.ROOT}, "the runtime cell moved"),
        ({"capabilities": frozenset({Capability.SYS_ADMIN})}, "the runtime cell moved"),
    ],
)
def test_invalidation_names_the_cell_that_moved(
    moved: dict[str, object], reason_fragment: str
) -> None:
    certified = _certified()
    assert certified.cell == _cell()
    drifted = invalidate_on_change(certified, cell=_cell(**moved))  # type: ignore[arg-type]
    assert drifted.state is CertificationState.INCOMPATIBLE
    assert drifted.grants_live_verification is False
    assert reason_fragment in drifted.reason
    assert certified.cell.label in drifted.reason
    assert _cell(**moved).label in drifted.reason  # type: ignore[arg-type]


def test_invalidation_also_covers_an_injector_version_change() -> None:
    drifted = invalidate_on_change(_certified(), injector_version="tc-netem 2.0.0")
    assert drifted.state is CertificationState.INCOMPATIBLE
    assert "injector/provider version moved" in drifted.reason
    assert "1.9.0" in drifted.reason
    assert "2.0.0" in drifted.reason


def test_invalidation_is_a_no_op_when_the_cell_and_injector_are_unchanged() -> None:
    certified = _certified()
    assert invalidate_on_change(certified, cell=_cell()) is certified
    assert invalidate_on_change(certified, cell=_cell(), injector_version="tc-netem 1.9.0") is (
        certified
    )
    assert invalidate_on_change(certified) is certified


def test_drift_and_a_failed_re_run_can_both_be_recorded() -> None:
    drifted = invalidate_on_change(_certified(), cell=_cell(kernel_version="6.14.0"))
    assert drifted.state is CertificationState.INCOMPATIBLE
    assert mark_incompatible(drifted, reason="second drift") is drifted


def test_a_terminal_record_without_a_reason_cannot_be_built() -> None:
    with pytest.raises(ValidationError, match="incompatible without saying why"):
        CertificationRecord.model_validate(
            {
                **_certified().model_dump(),
                "state": CertificationState.INCOMPATIBLE,
                "reason": "",
            }
        )


# ── the record store's contribution to the reported level ───────────────────


def _run_observations() -> tuple[Observation, ...]:
    return (
        Observation(
            stage="injected",
            probe="latency",
            baseline=10.0,
            observed=250.0,
            tolerance=5.0,
            passed=True,
        ),
        Observation(
            stage="undo", probe="latency", baseline=10.0, observed=11.0, tolerance=5.0, passed=True
        ),
        Observation(
            stage="residue",
            probe="latency",
            baseline=10.0,
            observed=10.5,
            tolerance=5.0,
            passed=True,
        ),
    )


def _run_bundles() -> BundleRef:
    return BundleRef(
        bundle_hash=_HASH,
        mayhem_version="1.1.0.test",
        bundle_path="/tmp/evidence/bundle.json",
        digests=dict.fromkeys(REQUIRED_BUNDLE_DIGESTS, _DIGEST),
    )


def _live_store() -> EvidenceStore:
    """A run store that, on its own, already earns ``verified-live``."""
    fault = definition_for(FAULT_ID)
    store = EvidenceStore()
    for lane in REQUIRED_LIVE_ENGINES:
        store = store.record(
            LiveRunRecord(
                fault_id=fault.id,
                engine=lane.value,
                platform="linux/amd64",
                run_id=f"cert-{lane.value}",
                environment="fixture-stack",
                target="fixture-api",
                observed_effect=fault.observable_effect,
                undo_performed=True,
                undo_description="write-ahead undo and verification probe",
                started_at=_NOW,
                finished_at=_NOW + timedelta(seconds=1),
                bundle=_run_bundles(),
                observations=_run_observations(),
            )
        )
    return store


def _probe() -> CatalogProbe:
    return build_probe(
        definition_for(FAULT_ID),
        executor_registered=lambda _fault_id: True,
        compensation_registered=lambda _fault_id: True,
        unit_evidence=("tests/unit/test_certification.py",),
    )


def _decision(records: Mapping[str, Sequence[CertificationRecord]] | None) -> PromotionDecision:
    return evaluate_maturity(
        definition_for(FAULT_ID),
        probe=_probe(),
        store=_live_store(),
        records=records,
    )


def test_certified_records_leave_the_pre_existing_decision_untouched() -> None:
    decision = _decision(_certified_pair())
    assert decision.maturity is MaturityLevel.VERIFIED_LIVE
    assert not any(CERTIFICATION_RECORDED in refusal for refusal in decision.refusals)


def test_deleting_the_evidence_drops_the_level_with_it() -> None:
    """The overlay's whole promise: no record, no live badge."""
    before = _decision(_certified_pair())
    assert before.maturity is MaturityLevel.VERIFIED_LIVE

    after = _decision({})
    assert after.maturity is MaturityLevel.VERIFIED_UNIT
    assert after.live_verified is False
    assert after.meaning == MATURITY_MEANING[MaturityLevel.VERIFIED_UNIT]
    refusal = next(r for r in after.refusals if CERTIFICATION_RECORDED in r)
    assert "no certified certification record for proc.pause on docker, podman" in refusal
    assert "certification record" in refusal and "observed" in refusal


def test_a_record_store_that_is_not_supplied_leaves_the_old_behaviour_alone() -> None:
    decision = evaluate_maturity(
        definition_for(FAULT_ID),
        probe=_probe(),
        store=_live_store(),
    )
    assert decision.maturity is MaturityLevel.VERIFIED_LIVE
    assert not any(CERTIFICATION_RECORDED in r for r in decision.refusals)


def test_expiry_demotes_the_reported_level_through_the_engine() -> None:
    records = _certified_pair()
    lapsed = {
        fault_id: tuple(
            expire_by_time(record, now=_AFTER) if index == 0 else record
            for index, record in enumerate(entries)
        )
        for fault_id, entries in records.items()
    }
    assert all(not entry.grants_live_verification for entry in lapsed[FAULT_ID][:1])
    decision = _decision(lapsed)
    assert decision.maturity is MaturityLevel.VERIFIED_UNIT
    assert "no certified certification record for proc.pause on docker" in (
        next(r for r in decision.refusals if CERTIFICATION_RECORDED in r)
    )


def test_invalidation_on_an_engine_change_demotes_the_reported_level() -> None:
    records = _certified_pair()
    drifted = {
        fault_id: (
            invalidate_on_change(entries[0], cell=_cell(engine_version="25.0.3")),
            *entries[1:],
        )
        for fault_id, entries in records.items()
    }
    decision = _decision(drifted)
    assert decision.maturity is MaturityLevel.VERIFIED_UNIT
    assert "on docker" in next(r for r in decision.refusals if CERTIFICATION_RECORDED in r)


def test_an_expiring_record_still_holds_the_badge() -> None:
    records = _certified_pair()
    expiring = {
        fault_id: tuple(
            expire_by_time(record, now=_INSIDE_WINDOW) if index == 0 else record
            for index, record in enumerate(entries)
        )
        for fault_id, entries in records.items()
    }
    assert _decision(expiring).maturity is MaturityLevel.VERIFIED_LIVE


def test_a_failed_record_withdraws_the_claim() -> None:
    records = _certified_pair()
    failed = {
        fault_id: (mark_failed(entries[0], reason="re-run regressed"), *entries[1:])
        for fault_id, entries in records.items()
    }
    decision = _decision(failed)
    assert decision.maturity is MaturityLevel.VERIFIED_UNIT
    assert "on docker" in next(r for r in decision.refusals if CERTIFICATION_RECORDED in r)


def test_certification_cannot_lift_a_fault_whose_run_evidence_is_missing() -> None:
    """The gate caps the ladder; it never climbs it."""
    decision = evaluate_maturity(
        definition_for(FAULT_ID),
        probe=_probe(),
        store=EvidenceStore(),
        records=_certified_pair(),
    )
    assert decision.maturity is MaturityLevel.VERIFIED_UNIT
    assert not any(CERTIFICATION_RECORDED in r for r in decision.refusals)
    assert decision.live_record_count == 0


def test_records_about_another_fault_do_not_certify_this_one() -> None:
    records: dict[str, tuple[CertificationRecord, ...]] = {
        "process.stop": (_certified().model_copy(update={"fault_id": "process.stop"}),)
    }
    decision = _decision(records)
    assert decision.maturity is MaturityLevel.VERIFIED_UNIT


def test_certified_engines_counts_only_records_that_still_grant() -> None:
    certified = _certified(_cell(engine=EngineLane.DOCKER))
    podman = _certified(_cell(engine=EngineLane.PODMAN))
    assert certified_engines((certified, podman)) == {EngineLane.DOCKER, EngineLane.PODMAN}
    assert certified_engines((expire_by_time(certified, now=_AFTER), podman)) == {EngineLane.PODMAN}
    assert certified_engines((_pending(),)) == frozenset()
    assert certified_engines(()) == frozenset()


# ── the domain law, restated where the module lives ─────────────────────────


_FORBIDDEN_STDLIB = frozenset({"asyncio", "socket", "subprocess", "sqlite3", "pathlib", "os"})
_FORBIDDEN_LAYERS = ("mayhem.toolkit", "mayhem.agents", "mayhem.controller", "mayhem.infra")


def test_certification_imports_nothing_the_domain_may_not_import() -> None:
    source = Path(certification_module.__file__).read_text(encoding="utf-8")
    imported: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            imported.add(node.module)
    assert not imported & _FORBIDDEN_STDLIB
    assert not [name for name in sorted(imported) if name.startswith(_FORBIDDEN_LAYERS)]
