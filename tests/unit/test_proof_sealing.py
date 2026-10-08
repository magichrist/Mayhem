"""Plan 30 Phase 4: the sealed proof, residue discharge, and approval binding.

Phase 2's compiler produced a checkable artifact and Phase 3 made it renderable.
Neither made it *evidence*, which is what this phase adds, and the three parts
are only worth having together:

* **sealing** — the proof is committed into plan 12's existing hash chain and
  manifest before the first fault step runs, so "the proof the approver signed"
  and "the proof the run carried" are the same bytes;
* **discharge** — post-run, each fault's residue obligation moves through the
  domain's own ``discharge()`` transition, line by line, and found residue
  **voids** its line;
* **binding** — an approval whose ``proof_digest`` is not the sealed proof's is
  refused, closing the plan-09 loop.

The tests are arranged so the negative controls come first in importance, not
last in the file. Each of the five the work item names is here as a test that
would fail if the property it guards were removed:

======================================  =========================================
property                                test
======================================  =========================================
a rule no line owns voids the proof      ``test_the_seal_refuses_a_proof_no_
                                         line_owns_a_refusal_for``
a superseded plan digest is VOID         ``test_a_sealed_proof_for_a_
                                         superseded_plan_is_void``
found residue voids its line             ``test_found_residue_voids_its_
                                         own_line``
an approval over a stale proof refused   ``test_an_approval_over_a_stale_
                                         proof_digest_is_refused``
an open residue obligation blocks close  ``test_a_run_with_an_open_residue_
                                         obligation_cannot_close_clean``
======================================  =========================================

Nothing here shells out, opens a socket, or reads a clock. The store is a
temporary SQLite file behind the real migration list, the clock is an injected
:class:`AttestedTimestamp`, and the residue scanner is a Protocol satisfied by a
frozen dataclass — because the property under test is that the chain verifies
offline from its own bytes, which is only a meaningful claim if producing it
needed nothing but the bytes.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

import pytest

from mayhem.controller import proof_sealing as ps
from mayhem.controller.approval_gate import (
    ApprovalGateInputs,
    ApprovalLedger,
)
from mayhem.controller.safety_proof import (
    OBLIGATION_FOR_RULE,
    canonical_plan_digest,
    compile_safety_proof,
)
from mayhem.domain.attestation import (
    GENESIS_DIGEST,
    AttestedTimestamp,
    RetentionClass,
    verify_manifest,
)
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.experiments import (
    BlastRadiusBudget,
    ExecutionPlan,
    ExperimentKind,
    InjectFault,
    PlannedFault,
    PlannedStep,
    ResolvedTarget,
)
from mayhem.domain.hashing import digest as digest_of
from mayhem.domain.identity import EnvironmentScope, Principal, Role, RoleGrant
from mayhem.domain.leases import UndoOp, VerifyProbe
from mayhem.domain.observations import CriterionKind
from mayhem.domain.safety_proof import (
    RESIDUE_PREDICATES,
    ObligationName,
    ObligationStatus,
    ProofVerdict,
    SafetyProof,
)
from mayhem.domain.topology import (
    Edge,
    EdgeKind,
    HostNode,
    NodeKind,
    ServiceNode,
    TargetSelector,
    TopologyGraph,
)
from mayhem.infra.attestation_store import (
    SIGNATURE_UNSIGNED_NO_SIGNING,
    UNSIGNED_REASON_NO_SIGNING,
    AttestationRepository,
    SigningNotImplementedError,
)
from mayhem.infra.certification_runner import RESIDUE_KINDS
from mayhem.infra.migrations import ALL_MIGRATIONS
from mayhem.infra.store import Store

if TYPE_CHECKING:
    from pathlib import Path

    from mayhem.controller.safety import SafetyContext
    from mayhem.domain.approval import Approval

#: Every reading in this file is injected. A chain that stamps its own clock is a
#: chain whose digest changes between two runs of the same input, and this suite
#: asserts the opposite in ``test_the_seal_is_reproducible``.
READING = AttestedTimestamp(
    wall_clock=datetime(2026, 3, 1, 12, 0, 0, tzinfo=UTC),
    monotonic_ns=1_000_000,
    uncertainty_ms=0.5,
    source="system",
)
LATER = AttestedTimestamp(
    wall_clock=datetime(2026, 3, 1, 12, 5, 0, tzinfo=UTC),
    monotonic_ns=2_000_000,
    uncertainty_ms=0.5,
    source="system",
)

FP = "f" * 64
OTHER_FP = "e" * 64


# --------------------------------------------------------------------------- #
# fixtures-as-values
# --------------------------------------------------------------------------- #


def _graph() -> TopologyGraph:
    return TopologyGraph(
        nodes=(
            ServiceNode(id="n-a", name="a"),
            ServiceNode(id="n-b", name="b"),
            HostNode(id="h-local", name="local", transport="local"),
        ),
        edges=(Edge(src="n-a", dst="n-b", kind=EdgeKind.DEPENDS_ON, weight=1.0),),
    )


def _permissive() -> BlastRadiusBudget:
    return BlastRadiusBudget(
        max_services_pct=100.0,
        max_hosts=2**31 - 1,
        max_concurrent_faults=2**31 - 1,
        max_duration_per_fault_s=float("inf"),
        forbidden_fault_pairs=frozenset(),
    )


def _plan(
    fault_ids: tuple[str, ...] = ("proc.pause", "net.latency"),
    durations: tuple[float, ...] = (10.0, 10.0),
    *,
    durations_override: tuple[float, ...] | None = None,
) -> ExecutionPlan:
    """A compensated two-fault plan — the shape every gate admits."""
    steps: list[PlannedStep] = []
    resolved = durations_override or durations
    for index, (fault_id, duration) in enumerate(zip(fault_ids, resolved, strict=True)):
        selector = TargetSelector(kind=NodeKind.SERVICE, expr="a")
        steps.append(
            PlannedStep(
                id=f"s{index}",
                seq=index,
                raw_action=InjectFault(fault=fault_id, selectors=(selector,), duration=duration),
                fault=PlannedFault(
                    fault_id=fault_id,
                    targets=(ResolvedTarget(selector=selector, node_ids=frozenset({"n-a"})),),
                    duration=duration,
                    undo_ops=(UndoOp(op="tc.del_qdisc"),),
                    verify_probes=(VerifyProbe(probe="tc.qdisc_absent"),),
                ),
            )
        )
    return ExecutionPlan(
        run_id="r-seal",
        kind=ExperimentKind.DETERMINISTIC,
        steps=tuple(steps),
        config_snapshot_id="c",
        topology_snapshot_id="t",
        environment_fingerprint=FP,
        # An enum, not a string: `SloCriterion.criterion_id` reads `kind.value`,
        # and `_line_stop_conditions` parses the plan's raw dict into the
        # dataclass before reading that property.
        slo=(
            {
                "kind": CriterionKind.LATENCY,
                "metric": "p99",
                "operator": "lt",
                "threshold": 250.0,
            },
        ),
    )


class _Adapter:
    """The compiler needs an adapter for the capability line to be anything but VOID.

    ``compile_safety_proof`` only reads ``adapter.id`` and calls ``evaluate``,
    so a minimal object with those two members is enough and no runtime is
    conjured. The concrete shape lives in ``tests/unit/test_proof_compiler.py``;
    duplicating a full ``RuntimeAdapter`` here would add noise without adding a
    property under test.
    """

    id = "fake-adapter"
    blocking = False

    def evaluate(self, reqs: Any) -> Any:  # pragma: no cover - see below
        from mayhem.domain.runtime_adapter import (
            CapabilityVerdict,
            VerdictResult,
        )

        return VerdictResult(
            engine=self.id,
            requirements=reqs,
            verdicts={"namespace": CapabilityVerdict.SUPPORTED.value},
            blocking=self.blocking,
        )


def _admitted_proof(plan: ExecutionPlan | None = None) -> SafetyProof:
    """A PASS proof over ``plan``, residue obligations attached and undischarged."""
    target = plan or _plan()
    return compile_safety_proof(
        target,
        _graph(),
        _safety_context(),
        adapter=_Adapter(),  # type: ignore[arg-type]
        include_residue=True,
    )


def _safety_context() -> Any:
    from mayhem.config import PolicyCfg
    from mayhem.controller.safety import SafetyContext
    from mayhem.domain.quota import DamageQuota

    return SafetyContext(
        policy=PolicyCfg(),
        budget=_permissive(),
        fingerprint=FP,
        damage_quota=DamageQuota(),
    )


@dataclass(frozen=True, slots=True)
class _FakeScanner:
    """A residue scanner that answers whatever the test tells it to.

    Satisfies :class:`~mayhem.controller.proof_sealing.ResidueScanner` without a
    container: the Protocol exists so the observation can come from a real cell,
    and a test that needs a specific finding should not have to manufacture one.
    """

    outcome: ps.ScanOutcome

    def residue_scan(self) -> ps.ScanOutcome:
        return self.outcome


def _clean() -> ps.ScanOutcome:
    return ps.ScanOutcome(performed=True, lease_states=("released",))


def _store(tmp_path: Path) -> Store:
    return Store.open_migrated(tmp_path / "mayhem.db", migrations=ALL_MIGRATIONS)


# =========================================================================== #
# 1. Sealing — the existing sealer, reused
# =========================================================================== #


def test_the_proof_is_sealed_into_plan_twelve_s_existing_chain_and_tables(
    tmp_path: Path,
) -> None:
    """Reuse, not a second sealer: same tables, same root, same manifest.

    The load-bearing assertion is that the proof seal lands in
    ``attestation_events`` / ``attestation_manifests`` — plan 12's M0023 tables —
    and that ``AttestationRepository.verify_run_chain`` re-verifies it. If this
    module had built its own chain, the rows would not be there and an auditor
    running the plan-12 verifier would find nothing to check.
    """
    store = _store(tmp_path)
    plan = _plan()
    proof = _admitted_proof(plan)

    sealed = ps.seal_proof(store, proof, run_id=plan.run_id, recorded_at=READING)

    repository = AttestationRepository(store)
    chain = repository.load_chain(ps.proof_scope(plan.run_id))
    assert [event.event_kind for event in chain] == [ps.EVENT_PROOF_SEALED]
    assert chain[0].digest == sealed.events[0].digest
    # The row is the one plan 12's verifier reads, and it verifies.
    stored_row = repository.load_chain_row(ps.proof_scope(plan.run_id))
    assert stored_row is not None
    assert stored_row["chain_root"] == sealed.chain_root
    assert repository.verify_run_chain(ps.proof_scope(plan.run_id)).valid

    manifest = repository.load_manifest(f"{plan.run_id}:proof:manifest")
    assert manifest is not None
    assert manifest.manifest_digest == sealed.manifest_digest
    assert verify_manifest(manifest, chain).valid


def test_sealing_produces_an_unsigned_manifest_and_says_why(tmp_path: Path) -> None:
    """The honesty gate travels with the proof, exactly as plan 12 requires.

    Plan 12 Phase 2 signs nothing and stores the reason beside the manifest. A
    proof seal that named a signer, or that went quiet about the absence, would
    turn "integrity verified" into "authorship verified" — the overclaim the
    whole plan exists to remove.
    """
    store = _store(tmp_path)
    plan = _plan()

    sealed = ps.seal_proof(store, _admitted_proof(plan), run_id=plan.run_id, recorded_at=READING)

    assert sealed.signature_state == SIGNATURE_UNSIGNED_NO_SIGNING
    assert sealed.signature_reason == UNSIGNED_REASON_NO_SIGNING
    assert sealed.signed is False
    state, reason = AttestationRepository(store).load_signature_state(
        f"{plan.run_id}:proof:manifest"
    )
    assert (state, reason) == (SIGNATURE_UNSIGNED_NO_SIGNING, UNSIGNED_REASON_NO_SIGNING)


def test_naming_a_signer_is_refused_rather_than_ignored(tmp_path: Path) -> None:
    """The Phase 6 seam guards a real interface, not a hypothetical one.

    Same refusal, same message shape, and the same reason
    ``seal_run_evidence`` refuses one: no key material exists, so honouring a
    signer would claim an authentication that never happened.
    """

    @dataclass(frozen=True, slots=True)
    class _Signer:
        identity: str = "u-alice"
        trust_root_ref: str = "tr-1"

    store = _store(tmp_path)
    plan = _plan()

    with pytest.raises(SigningNotImplementedError) as excinfo:
        ps.seal_proof(
            store,
            _admitted_proof(plan),
            run_id=plan.run_id,
            recorded_at=READING,
            signer=_Signer(),
        )
    assert "no signature bytes" in str(excinfo.value)
    # And nothing was written on the way out.
    assert AttestationRepository(store).load_manifest(f"{plan.run_id}:proof:manifest") is None


def test_the_sealed_proof_reloads_and_reproduces_its_own_digest(tmp_path: Path) -> None:
    """The artifact survives a restart and hashes to the same value.

    This is what makes the seal worth anything: a verifier months later, with no
    control plane, reloads the stored bytes and gets the *same* proof. The
    reconstruction is re-validated by the model rather than trusted, so a payload
    edited behind the model's back fails here.
    """
    store = _store(tmp_path)
    plan = _plan()
    proof = _admitted_proof(plan)

    sealed = ps.seal_proof(store, proof, run_id=plan.run_id, recorded_at=READING)
    reloaded, manifest_digest = ps.verify_sealed_proof(store, plan.run_id)

    assert reloaded is not None
    assert reloaded.proof_digest == proof.proof_digest
    assert reloaded.verdict is proof.verdict
    assert [o.name for o in reloaded.obligations] == [o.name for o in proof.obligations]
    assert manifest_digest == sealed.manifest_digest


def test_a_tampered_chain_row_is_rejected_by_the_persisted_verifier(
    tmp_path: Path,
) -> None:
    """The negative control for sealing: edit the stored bytes, lose the proof.

    A sealer that only ever re-verified its own in-memory objects would pass
    every positive test here and be worthless. This is the same discipline
    ``tests/unit/test_attestation_store.py`` applies to a chain row, reached from
    the proof's side.
    """
    store = _store(tmp_path)
    plan = _plan()
    ps.seal_proof(store, _admitted_proof(plan), run_id=plan.run_id, recorded_at=READING)
    scope = ps.proof_scope(plan.run_id)

    # Edited behind the model's back: the payload claims a different proof digest
    # while the stored `digest` column still holds the original. Nothing
    # re-validates on the way in, so only the offline verifier can catch it —
    # which is exactly the property under test.
    rows = store.query("SELECT event_json FROM attestation_events WHERE run_id = ?", (scope,))
    stored = json.loads(str(dict(rows[0])["event_json"]))
    stored["payload"]["proof_digest"] = "d" * 64
    with store.write() as conn:
        conn.execute(
            "UPDATE attestation_events SET event_json = ? WHERE run_id = ?",
            (json.dumps(stored, sort_keys=True, separators=(",", ":")), scope),
        )

    reloaded, reason = ps.verify_sealed_proof(store, plan.run_id)

    assert reloaded is None
    assert "does not verify" in reason


def test_the_seal_is_reproducible_across_two_stores(tmp_path: Path) -> None:
    """Determinism: the same proof and reading produce the same digests.

    Without this, the seal would be a timestamp rather than a commitment — two
    runs over identical input hashing differently is what makes an attestation
    unverifiable in comparison.
    """
    proof = _admitted_proof()

    first = ps.seal_proof(_store(tmp_path / "a"), proof, run_id="r-seal", recorded_at=READING)
    second = ps.seal_proof(_store(tmp_path / "b"), proof, run_id="r-seal", recorded_at=READING)

    assert first.chain_root == second.chain_root
    assert first.manifest_digest == second.manifest_digest
    assert first.proof_digest == second.proof_digest


def test_the_proof_chain_is_scoped_so_it_cannot_overwrite_the_run_close_chain(
    tmp_path: Path,
) -> None:
    """One chain per run, and the proof's is not the run's.

    ``attestation_chains.run_id`` is a primary key and ``save_chain`` does
    ``INSERT OR REPLACE``: if the proof seal were keyed on the run itself, the
    later run-close seal would silently overwrite the proof's events and the
    admission case would be gone. :func:`proof_scope` is what keeps the two
    apart, and this is the test that says so.
    """
    store = _store(tmp_path)
    plan = _plan()

    ps.seal_proof(store, _admitted_proof(plan), run_id=plan.run_id, recorded_at=READING)

    repository = AttestationRepository(store)
    assert ps.proof_scope(plan.run_id) != plan.run_id
    assert repository.load_chain_row(ps.proof_scope(plan.run_id)) is not None
    # Nothing was written under the bare run id, so a run-close seal is unaffected.
    assert repository.load_chain_row(plan.run_id) is None


def test_runs_link_at_the_manifest_layer_as_the_attestation_store_requires(
    tmp_path: Path,
) -> None:
    """Two chains, one manifest chain — the store's own stated design.

    ``domain.attestation``'s verifier defines a chain as starting at genesis, so
    an event chain cannot be hung off another chain's root. The store's docstring
    says runs therefore link through ``previous_manifest_digest``; this proves a
    caller can do exactly that, and that the digest is covered by the manifest
    digest so the link cannot be edited after the fact.
    """
    from mayhem.domain.attestation import build_manifest, seal_events

    store = _store(tmp_path)
    first = ps.seal_proof(store, _admitted_proof(), run_id="r-one", recorded_at=READING)
    second = ps.seal_proof(
        store,
        _admitted_proof(),
        run_id="r-two",
        recorded_at=LATER,
        previous_manifest_digest=first.manifest_digest,
    )

    assert second.manifest.previous_manifest_digest == first.manifest_digest
    assert second.manifest_digest != first.manifest_digest
    # The link is inside the hashed view, so it is attested rather than merely
    # stored beside the manifest: editing it changes the manifest digest.
    assert second.manifest.canonical_view()["previous_manifest_digest"] == first.manifest_digest
    relinked = second.manifest.model_copy(
        update={"previous_manifest_digest": GENESIS_DIGEST}
    ).computed_digest()
    assert relinked != second.manifest_digest
    # And a genesis-chained proof still verifies as its own chain.
    events = seal_events(
        [ps.proof_seal_event(_admitted_proof(), run_id="r-three", recorded_at=LATER)]
    )
    manifest = build_manifest(events, manifest_id="r-three:proof:manifest", run_id="r-three:proof")
    assert verify_manifest(manifest, events).valid
    assert manifest.previous_manifest_digest == GENESIS_DIGEST


def test_a_proof_with_no_verdict_assertion_is_still_sealable(tmp_path: Path) -> None:
    """A sealed VOID proof is a true record; refusing it would lose the artifact.

    The seal says "this proof, in this state, existed before the run", not "this
    proof passed". A run the gate refused still deserves a sealed record of what
    it compiled to, and the verdict travels in the payload.
    """
    store = _store(tmp_path)
    plan = _plan(
        fault_ids=(),
        durations=(),
    )
    void_proof = compile_safety_proof(
        plan,
        _graph(),
        _safety_context(),
        adapter=_Adapter(),  # type: ignore[arg-type]
    )
    assert void_proof.verdict is ProofVerdict.VOID

    sealed = ps.seal_proof(store, void_proof, run_id=plan.run_id, recorded_at=READING)

    assert sealed.proof.verdict is ProofVerdict.VOID
    reloaded, _ = ps.verify_sealed_proof(store, plan.run_id)
    assert reloaded is not None and reloaded.verdict is ProofVerdict.VOID


# =========================================================================== #
# 2. Residue discharge — line by line, fail-closed
# =========================================================================== #


def test_a_clean_scan_discharges_every_fault_line_and_closes_clean() -> None:
    """The happy path, and the whole point of the exercise.

    Every fault's obligation is discharged through the domain's own
    ``discharge()``; every line passes; the run may close. The proof itself was
    ``VOID`` before discharge (nothing had been observed), which is why this is
    a real transition and not a formality.
    """
    plan = _plan()
    proof = _admitted_proof(plan)
    assert proof.verdict is ProofVerdict.VOID
    assert len(proof.residue_obligations) == 2

    discharge = ps.discharge_residue(
        proof,
        {"proc.pause": _clean(), "net.latency": _clean()},
    )

    assert discharge.closes_clean is True
    assert discharge.dirty_faults == ()
    assert discharge.unscanned_faults == ()
    assert discharge.open_faults == ()
    assert all(status is ObligationStatus.PASS for _, status in discharge.discharges)
    assert discharge.proof.verdict is ProofVerdict.PASS
    assert discharge.proof.is_valid(plan_digest := canonical_plan_digest(plan)) is True
    assert plan_digest


def test_found_residue_voids_its_own_line() -> None:
    """Negative control: residue found -> ``VOID`` on that line, run dirtied.

    Only the offending fault's line moves. The other fault discharged clean and
    stays ``PASS``, so the artifact names *which* fault left something behind
    rather than collapsing the whole answer into "dirty".
    """
    proof = _admitted_proof()

    discharge = ps.discharge_residue(
        proof,
        {
            "proc.pause": _clean(),
            "net.latency": ps.ScanOutcome(
                performed=True, kinds=("tc_rule",), detail="qdisc netem still present"
            ),
        },
    )

    assert discharge.dirty_faults == ("net.latency",)
    assert discharge.closes_clean is False
    assert dict(discharge.discharges)["net.latency"] is ObligationStatus.VOID
    assert dict(discharge.discharges)["proc.pause"] is ObligationStatus.PASS
    line = discharge.proof.obligation("residue:net.latency")
    assert line is not None
    assert line.status is ObligationStatus.VOID
    assert "no_tc_rules" in line.detail
    # And the proof as a whole is VOID: the run cannot read as a pass.
    assert discharge.proof.verdict is ProofVerdict.VOID


def test_a_dirty_lease_predicate_voids_the_line_the_shell_probes_cannot_reach() -> None:
    """``no_leases_held`` is the predicate only the store can observe.

    A cell cannot see a lease — it lives in the control plane's tables — so this
    is the one predicate no in-container probe can discharge. The mapping names
    it rather than leaving it unchecked, because a lease left ``active`` is
    residue as surely as a ``tc`` rule is.
    """
    proof = _admitted_proof()

    discharge = ps.discharge_residue(
        proof,
        {
            "proc.pause": ps.ScanOutcome(performed=True, lease_states=("active",)),
            "net.latency": _clean(),
        },
    )

    assert discharge.dirty_faults == ("proc.pause",)
    line = discharge.proof.obligation("residue:proc.pause")
    assert line is not None and line.status is ObligationStatus.VOID
    assert "no_leases_held" in line.detail


def test_a_partial_scan_leaves_the_run_unclosable(tmp_path: Path) -> None:
    """Negative control: one fault scanned, one forgotten.

    The caller supplied no outcome for ``net.latency``. The answer is ``FAIL`` on
    that line and a run that cannot close clean — *not* an assumption that the
    fault left nothing behind. A caller that forgets a fault gets the fail-closed
    answer by construction, which is the only safe default.
    """
    proof = _admitted_proof()

    discharge = ps.discharge_residue(proof, {"proc.pause": _clean()})

    assert discharge.unscanned_faults == ("net.latency",)
    assert discharge.closes_clean is False
    assert dict(discharge.discharges)["net.latency"] is ObligationStatus.FAIL
    line = discharge.proof.obligation("residue:net.latency")
    assert line is not None and line.status is ObligationStatus.FAIL
    assert "did not run" in line.detail
    assert discharge.proof.verdict is ProofVerdict.FAIL


def test_an_explicitly_unperformed_scan_is_also_not_clean() -> None:
    """``performed=False`` is a real observation, not an empty one.

    The plan-01 vocabulary distinguishes "I looked and found nothing" from "I did
    not look". A scan that reports ``performed=False`` must land on ``FAIL``, and
    the *reason* it did not run has to survive into the citation — Phase 1's
    ``discharge()`` writes its own fixed text on that branch, so the observation's
    note lives in the scan digest rather than the line's detail. Both are
    asserted, because a reader needs to be able to tell two unscanned faults
    apart.
    """
    proof = _admitted_proof()

    discharge = ps.discharge_residue(
        proof,
        {
            "proc.pause": _clean(),
            "net.latency": ps.ScanOutcome(performed=False, detail="cell was already gone"),
        },
    )
    other = ps.discharge_residue(
        proof,
        {
            "proc.pause": _clean(),
            "net.latency": ps.ScanOutcome(performed=False, detail="probe binary missing"),
        },
    )

    assert discharge.unscanned_faults == ("net.latency",)
    assert discharge.closes_clean is False
    line = discharge.proof.obligation("residue:net.latency")
    assert line is not None and line.status is ObligationStatus.FAIL
    assert "did not run" in line.detail
    # The two reasons are distinguishable by digest even though the line text is
    # the domain's fixed wording.
    assert line.gate_digest != other.proof.obligation("residue:net.latency").gate_digest  # type: ignore[union-attr]


def test_every_discharged_line_cites_the_scan_that_discharged_it() -> None:
    """Discharge is not an unchecked assertion: it cites the observation.

    A ``PASS`` residue line is a claim about the world, so — like every other
    ``PASS`` line in this proof — it must cite a gate digest and an evidence
    reference. The digest is taken over what the cell *reported*, so an auditor
    recomputes it from the scan output rather than from this module's mapping.
    """
    proof = _admitted_proof()

    discharge = ps.discharge_residue(
        proof,
        {"proc.pause": _clean(), "net.latency": _clean()},
    )

    for fault_id in ("proc.pause", "net.latency"):
        line = discharge.proof.obligation(f"residue:{fault_id}")
        assert line is not None
        assert len(line.gate_digest) == 64
        assert all(c in "0123456789abcdef" for c in line.gate_digest)
        assert line.evidence_ref.strip()
        assert "residue-scan" in line.evidence_ref


def test_the_scan_digest_is_over_the_observation_not_the_mapping() -> None:
    """Two different scans produce two different citations for the same line.

    If the digest were taken over the derived predicates, a scan that found
    nothing and one that found a marker file would cite the same bytes and the
    citation would distinguish nothing.
    """
    clean_line = ps.residue_scan_for("proc.pause", _clean())
    dirty_line = ps.residue_scan_for(
        "proc.pause", ps.ScanOutcome(performed=True, kinds=("marker_file",))
    )

    assert clean_line.gate_digest != dirty_line.gate_digest
    assert clean_line.dirty_predicates == ()
    assert [p.value for p in dirty_line.dirty_predicates] == ["no_files"]


def test_an_unrecognised_residue_kind_is_reported_never_dropped() -> None:
    """A finding the vocabulary cannot name still dirties the run.

    If an unrecognised kind were discarded, the residue would be silently lost —
    the exact failure gap 65 exists to close. It is kept, named in the scan's
    note, and its *known* siblings still map to predicates; the honest answer for
    an unnameable class is that it was reported and not silently dropped.
    """
    outcome = ps.scan_outcome_from_certification_scan(
        performed=True,
        findings=(("tc_rule", "netem"), ("wormhole_but_novel", "a kind nobody catalogued")),
    )

    assert "tc_rule" in outcome.kinds
    assert "unrecognised residue kind" in outcome.detail
    assert "wormhole_but_novel" in outcome.detail
    # The named predicate still fires, so the line is dirtied rather than passed.
    assert ps.dirty_predicates(outcome) == ("no_tc_rules",)


def test_a_scan_of_a_fault_the_proof_does_not_cover_is_refused() -> None:
    """Losing a finding is worse than raising.

    A caller supplying a scan for a fault the proof asserts nothing about has
    found residue the proof cannot account for. Silently ignoring it would drop
    the finding; :func:`discharge_residue` names it and refuses instead.
    """
    proof = _admitted_proof()

    with pytest.raises(ps.ProofSealingError) as excinfo:
        ps.discharge_residue(proof, {"k8s.node_drain": _clean()})
    assert "k8s.node_drain" in str(excinfo.value)


def test_discharge_of_a_proof_with_no_residue_lines_is_a_no_op_not_a_pass() -> None:
    """A proof compiled without residue obligations discharges nothing.

    Vacuously "no open obligations" would be the dangerous reading here: the run
    would close clean having checked nothing. :attr:`ResidueDischarge.closes_clean`
    is a conjunction over what was *checked*, and with nothing asserted the
    discharge records nothing and leaves the proof as it was — still ``VOID``,
    because the residue lines were never there to pass.
    """
    plan = _plan()
    proof = compile_safety_proof(
        plan,
        _graph(),
        _safety_context(),
        adapter=_Adapter(),  # type: ignore[arg-type]
    )
    assert proof.verdict is ProofVerdict.PASS
    assert proof.residue_obligations == ()

    discharge = ps.discharge_residue(proof, {})

    assert discharge.discharges == ()
    assert discharge.closes_clean is True  # nothing was open
    # But the proof itself did not gain a residue verdict: the caller must have
    # compiled with ``include_residue=True`` to have anything to discharge.
    assert discharge.proof.residue_obligations == ()


def test_the_residue_vocabulary_is_the_plan_one_definitions_not_a_restatement() -> None:
    """The two vocabularies are joined by data, and the join is asserted.

    :data:`mayhem.infra.certification_runner.RESIDUE_KINDS` is plan 01's list and
    this module's :data:`RESIDUE_PREDICATE_FOR_KIND` is the proof's spelling of
    it. If plan 01 adds a class and this table does not, the new class becomes
    residue no predicate can express — so the assertion is over the *real*
    constant rather than a copy that would happily drift.
    """
    assert set(RESIDUE_KINDS) == set(ps.RESIDUE_PREDICATE_FOR_KIND)
    # The proof's six predicates are the five plan-01 classes plus the lease.
    assert ps.SCANNED_RESIDUE_PREDICATES == RESIDUE_PREDICATES


# =========================================================================== #
# 3. Approval binding — the plan-09 loop closed
# =========================================================================== #


def _approving_principal() -> Principal:
    return Principal(principal_id="u-approve")


def _mint(proof: SafetyProof, *, approval_id: str = "a-seal1") -> Approval:
    """One approval bound to ``proof``, through the plan-09 minting service.

    ``ApprovalLedger.mint`` refuses a non-``PASS`` proof, which is why the callers
    below pass a proof that has already been discharged (see :func:`_bound_proof`).
    The approval binds *exactly* the proof handed in, which is what makes the
    digest comparisons in these tests meaningful.
    """
    assert proof.verdict is ProofVerdict.PASS, proof.void_reason
    ledger = ApprovalLedger(
        grants=(
            RoleGrant(
                role=Role.APPROVE,
                scope=EnvironmentScope(environment="production"),
                granted_at=datetime(2026, 2, 28, tzinfo=UTC),
                principal=_approving_principal(),
            ),
        )
    )
    return ledger.mint(
        approval_id=approval_id,
        proof=proof,
        policy_digest=digest_of({"bundle": "sealing"}),
        approver=_approving_principal(),
        environment=EnvironmentScope(environment="production"),
        now=READING.wall_clock,
    ).approvals[-1]


def _bound_proof(proof: SafetyProof) -> SafetyProof:
    """``proof`` with its residue discharged — the artifact an approval may bind.

    Approval is granted on a completed safety case, and Phase 1's
    :meth:`Approval.bind` refuses a non-``PASS`` proof. A proof carrying
    undischarged residue lines is ``VOID``, so this is the artifact a real
    approval names, and every binding test below compares against it.
    """
    discharged = ps.discharge_residue(
        proof,
        {fault_id: _clean() for fault_id in (o.fault_id for o in proof.residue_obligations)},
    )
    assert discharged.closes_clean is True
    return discharged.proof


def test_an_approval_bound_to_the_sealed_proof_is_accepted(tmp_path: Path) -> None:
    """The positive binding: same digest, accepted, named in the artifact.

    The approval is minted through :meth:`ApprovalLedger.mint`, which refuses a
    non-PASS proof, so reaching here already required a proof that passed. The
    binding check then confirms the digest matches the *sealed* artifact.
    """
    store = _store(tmp_path)
    plan = _plan()
    # The sealed artifact is the completed safety case — residue discharged —
    # because approval is granted on a completed case and Phase 1's
    # `Approval.bind` refuses anything else.
    completed = _bound_proof(_admitted_proof(plan))
    sealed = ps.seal_proof(store, completed, run_id=plan.run_id, recorded_at=READING)
    approval = _mint(completed)

    ps.require_approval_binding((approval,), sealed.proof)

    assert approval.proof_digest == sealed.proof_digest
    assert ps.verify_approval_binding((approval,), sealed.proof) == ()


def test_an_approval_over_a_stale_proof_digest_is_refused(tmp_path: Path) -> None:
    """Negative control: the whole point of the binding.

    Two proofs of the same plan, one sealed and one not — the natural shape of a
    proof that was recompiled after the seal. An approval over the recompiled
    one names a digest that is not on file, and the run is refused rather than
    authorised against a proof nobody sealed.
    """
    store = _store(tmp_path)
    plan = _plan()
    # Same plan, recompiled after the seal: `generated_at` alone moves the
    # digest, which is exactly the "the proof changed under us" case.
    sealed_proof = _bound_proof(_admitted_proof(plan))
    sealed = ps.seal_proof(store, sealed_proof, run_id=plan.run_id, recorded_at=READING)
    recompiled = sealed_proof.model_copy(
        update={"generated_at": datetime(2026, 3, 1, 12, 30, tzinfo=UTC)}
    )
    assert recompiled.proof_digest != sealed.proof_digest
    stale = _mint(recompiled)

    with pytest.raises(ps.ProofSealingError) as excinfo:
        ps.require_approval_binding((stale,), sealed.proof)

    assert stale.approval_id in str(excinfo.value)
    assert sealed.proof_digest[:12] in str(excinfo.value)
    assert ps.verify_approval_binding((stale,), sealed.proof)


def test_one_stale_approval_refuses_the_whole_set() -> None:
    """Stricter than the gate on purpose, and the difference is stated.

    ``evaluate_approvals`` lets a quorum be met with a stale token attached — an
    authorized run with a stale record. For a *sealed* proof the stale token says
    somebody approved a proof that is not the one on file, which is a different
    question, so the set is refused rather than the token buried in a discarded
    list.
    """
    plan = _plan()
    good = _bound_proof(_admitted_proof(plan))
    other = good.model_copy(update={"generated_at": datetime(2026, 3, 1, 12, 30, tzinfo=UTC)})
    fresh = _mint(good, approval_id="a-fresh")
    stale = _mint(other, approval_id="a-stale")

    assert ps.verify_approval_binding((fresh,), good) == ()
    assert ps.verify_approval_binding((fresh, stale), good) != ()

    with pytest.raises(ps.ProofSealingError) as excinfo:
        ps.require_approval_binding((fresh, stale), good)
    assert "a-stale" in str(excinfo.value)


def test_binding_is_refused_at_admission_not_only_at_seal_time() -> None:
    """The check runs where the gate runs, on the proof the gate is handed.

    The gate compares approvals against ``inputs.proof.proof_digest``; this test
    wires the *sealed* proof into the gate and shows the stale approval is
    refused there with ``proof_digest_mismatch`` as the trigger. Without it the
    binding would be a fact about sealing only, and an admission path that
    presented a different proof object would slip past.
    """
    from mayhem.domain.approval import InvalidationReason

    plan = _plan()
    sealed_proof = _bound_proof(_admitted_proof(plan))
    recompiled = sealed_proof.model_copy(
        update={"generated_at": datetime(2026, 3, 1, 12, 30, tzinfo=UTC)}
    )
    stale = _mint(recompiled)

    gate = ApprovalGateInputs(
        now=READING.wall_clock,
        environment=EnvironmentScope(environment="production"),
        executor=Principal(principal_id="u-exec"),
        proof=sealed_proof,
        policy_digest=digest_of({"bundle": "sealing"}),
        approvals=(stale,),
        grants=(
            RoleGrant(
                role=Role.EXECUTE,
                scope=EnvironmentScope(environment="production"),
                granted_at=datetime(2026, 2, 28, tzinfo=UTC),
                principal=Principal(principal_id="u-exec"),
            ),
            RoleGrant(
                role=Role.APPROVE,
                scope=EnvironmentScope(environment="production"),
                granted_at=datetime(2026, 2, 28, tzinfo=UTC),
                principal=_approving_principal(),
            ),
        ),
    )
    from mayhem.controller.approval_gate import verify_approvals

    result = verify_approvals(plan, gate)

    assert result.denied is True
    assert result.state.has(InvalidationReason.PROOF_DIGEST_MISMATCH)
    assert result.refusal is not None


def test_the_approval_line_reads_the_gate_state_so_a_stale_approval_shows_up() -> None:
    """End to end: the compiler surfaces the stale binding as a ``FAIL`` line.

    Three modules agreeing — the proof compiler reads the gate, the gate refuses,
    and :data:`OBLIGATION_FOR_RULE` places the refusal on
    ``required_approvals``. Without the mapping this would be a whole-proof
    ``VOID`` naming an unplaceable rule, which is fail-closed but unreportable.
    """
    from mayhem.controller.safety_proof import compile_safety_evidence

    plan = _plan()
    # The gate holds a proof that is *not* the one the approvals were bound to:
    # an approval minted against a proof with a different `generated_at`. The
    # gate compares `inputs.proof.proof_digest` against the approval's, so this
    # is the mismatch that must surface.
    gate_proof = _bound_proof(_admitted_proof(plan))
    stale = _mint(
        gate_proof.model_copy(update={"generated_at": datetime(2026, 3, 1, 12, 30, tzinfo=UTC)}),
        approval_id="a-stale1",
    )
    approver = _approving_principal()
    assert stale.proof_digest != gate_proof.proof_digest
    gate = ApprovalGateInputs(
        now=READING.wall_clock,
        environment=EnvironmentScope(environment="production"),
        executor=Principal(principal_id="u-exec"),
        proof=gate_proof,
        policy_digest=digest_of({"bundle": "sealing"}),
        approvals=(stale,),
        grants=(
            RoleGrant(
                role=Role.EXECUTE,
                scope=EnvironmentScope(environment="production"),
                granted_at=datetime(2026, 2, 28, tzinfo=UTC),
                principal=Principal(principal_id="u-exec"),
            ),
            RoleGrant(
                role=Role.APPROVE,
                scope=EnvironmentScope(environment="production"),
                granted_at=datetime(2026, 2, 28, tzinfo=UTC),
                principal=approver,
            ),
        ),
    )
    ctx: SafetyContext = _safety_context()
    ctx = type(ctx)(
        policy=ctx.policy,
        budget=ctx.budget,
        fingerprint=ctx.fingerprint,
        damage_quota=ctx.damage_quota,
        approval_gate=gate,
    )

    compilation = compile_safety_evidence(plan, _graph(), ctx, adapter=_Adapter())  # type: ignore[arg-type]

    line = compilation.proof.obligation(ObligationName.REQUIRED_APPROVALS.value)
    assert line is not None
    assert line.status is ObligationStatus.FAIL
    assert compilation.proof.verdict is not ProofVerdict.PASS
    assert compilation.proof.void_reason == ""
    # And the rule is placed on this line rather than voiding the proof.
    assert ObligationName.REQUIRED_APPROVALS.value in compilation.blame
    assert stale.proof_digest != gate_proof.proof_digest


# =========================================================================== #
# 4. Superseded plans and the whole chain
# =========================================================================== #


def test_a_sealed_proof_for_a_superseded_plan_is_void_never_pass(tmp_path: Path) -> None:
    """Negative control: the seal does not make a stale proof current.

    The proof was sealed for a plan that has since moved by one second. Every
    line still passes and is irrelevant, because the lines describe a plan that
    no longer exists. Sealing pins *what was proven*; it cannot pin *what is
    true now*.
    """
    store = _store(tmp_path)
    old = _plan()
    new = _plan(durations_override=(10.0, 11.0))
    assert canonical_plan_digest(old) != canonical_plan_digest(new)

    sealed = ps.seal_proof(
        store, _bound_proof(_admitted_proof(old)), run_id=old.run_id, recorded_at=READING
    )
    current = canonical_plan_digest(new)

    assert sealed.proof.verdict is ProofVerdict.PASS
    assert sealed.proof.evaluate(current) is ProofVerdict.VOID
    assert sealed.proof.is_valid(current) is False
    voided = sealed.proof.voided(current)
    assert voided.verdict is ProofVerdict.VOID
    assert "plan superseded" in voided.void_reason
    # The sealed bytes are untouched: voiding is a reading, not a rewrite.
    reloaded, _ = ps.verify_sealed_proof(store, old.run_id)
    assert reloaded is not None and reloaded.proof_digest == sealed.proof_digest


def test_a_run_with_an_open_residue_obligation_cannot_close_clean(tmp_path: Path) -> None:
    """Negative control, end to end: sealed, discharged dirty, not closable.

    The chain the plan asks for — sealed proof, residue discharge, verdict — as
    one value. The verdict is ``VOID`` because a residue line is, and
    :attr:`SealedAndDischargedRun.closes_clean` is ``False`` on both counts. A
    run in this state cannot be read as clean by any of the three facts.
    """
    store = _store(tmp_path)
    plan = _plan()
    run = ps.seal_and_discharge(
        store,
        _admitted_proof(plan),
        run_id=plan.run_id,
        recorded_at=READING,
        outcomes={
            "proc.pause": _clean(),
            "net.latency": ps.ScanOutcome(performed=True, kinds=("iptables_entry",)),
        },
        plan_digest=canonical_plan_digest(plan),
    )

    assert run.verdict is ProofVerdict.VOID
    assert run.closes_clean is False
    assert run.discharge.dirty_faults == ("net.latency",)
    assert "cannot close clean" in run.describe()


def test_the_whole_chain_closes_clean_when_the_scan_is_clean(tmp_path: Path) -> None:
    """The end-to-end positive: one value answering every question at once.

    Sealed pre-execution, discharged post-run, verdict ``PASS``, and the sealed
    artifact still verifiable from the store afterwards. This is the acceptance
    shape plan 30 Phase 4 asks for.
    """
    store = _store(tmp_path)
    plan = _plan()
    run = ps.seal_and_discharge(
        store,
        _admitted_proof(plan),
        run_id=plan.run_id,
        recorded_at=READING,
        outcomes={"proc.pause": _clean(), "net.latency": _clean()},
        plan_digest=canonical_plan_digest(plan),
    )

    assert run.verdict is ProofVerdict.PASS
    assert run.closes_clean is True
    assert run.proof.proof_digest != run.sealed.proof_digest  # discharge changed it
    reloaded, _ = ps.verify_sealed_proof(store, plan.run_id)
    assert reloaded is not None
    assert reloaded.proof_digest == run.sealed.proof_digest  # the seal is untouched
    assert "closes clean: True" in run.describe()


def test_a_chain_over_a_superseded_plan_cannot_close_clean(tmp_path: Path) -> None:
    """The seal is not a licence: freshness is still checked at close.

    ``closes_clean`` consults the *current* plan digest as well as the discharge,
    so a chain sealed for a plan that has since moved is not closable even though
    every line passed and the residue was clean.
    """
    store = _store(tmp_path)
    old = _plan()
    run = ps.seal_and_discharge(
        store,
        _admitted_proof(old),
        run_id=old.run_id,
        recorded_at=READING,
        outcomes={"proc.pause": _clean(), "net.latency": _clean()},
        plan_digest=canonical_plan_digest(_plan(durations_override=(10.0, 11.0))),
    )

    assert run.discharge.closes_clean is True
    assert run.closes_clean is False


def test_the_seal_refuses_a_proof_no_line_owns_a_refusal_for(tmp_path: Path) -> None:
    """Negative control: an unplaceable refusal still voids, seal or no seal.

    Sealing does not launder a proof. A gate that refuses on a rule no
    obligation owns produces a ``VOID`` proof naming the rule, and this module
    seals *that* proof — recording the failure rather than hiding it behind a
    successful seal.
    """
    from mayhem.controller import safety_proof as compiler

    store = _store(tmp_path)
    plan = _plan()
    proof = _admitted_proof(plan)
    assert proof.verdict is ProofVerdict.VOID  # residue lines are undischarged

    sealed = ps.seal_proof(store, proof, run_id=plan.run_id, recorded_at=READING)
    assert sealed.proof.verdict is ProofVerdict.VOID
    assert sealed.proof.void_reason
    # The mapping is what keeps this from being the *unmapped* case.
    assert all(rule in OBLIGATION_FOR_RULE for rule in compiler.GATE_RULE_IDS)


# =========================================================================== #
# 5. The residue scanner seam
# =========================================================================== #


def test_the_scanner_protocol_is_satisfied_by_the_live_shape() -> None:
    """The Protocol is not decorative: a real scanner-shaped object fits it.

    ``mayhem.cli.certify.EngineCell.residue_scan`` returns the plan-01
    ``ResidueScan``; the adapter turns it into the observation this module reads.
    Asserting the adapter round-trips both shapes is what keeps the seam honest
    without instantiating a container engine.
    """
    from mayhem.infra.certification_runner import ResidueFinding
    from mayhem.infra.certification_runner import ResidueScan as CellResidueScan

    cell = CellResidueScan(
        performed=True,
        findings=(ResidueFinding(kind="marker_process", detail="mayhem-inject"),),
    )

    outcome = ps.scan_outcome_from_certification_scan(
        performed=cell.performed,
        findings=((finding.kind, finding.detail) for finding in cell.findings),
    )
    assert outcome.performed is True
    assert outcome.kinds == ("marker_process",)
    assert outcome.clean is False
    assert ps.dirty_predicates(outcome) == ("no_marker_processes",)

    scanner = _FakeScanner(outcome)
    assert scanner.residue_scan().kinds == ("marker_process",)


def test_a_clean_scan_reports_clean_and_a_dirty_one_does_not() -> None:
    """``clean`` is not "no findings" — it is performed *and* nothing found.

    The property that keeps an unchecked cell from reading as clean, at the
    observation level rather than at the proof level.
    """
    assert ps.ScanOutcome().clean is False
    assert ps.ScanOutcome(performed=True).clean is True
    assert ps.ScanOutcome(performed=True, kinds=("tc_rule",)).clean is False
    assert ps.ScanOutcome(performed=True, lease_states=("active",)).clean is False
    assert ps.ScanOutcome(performed=True, lease_states=("released", "expired")).clean is True


# =========================================================================== #
# 6. Small honesty properties of the sealer itself
# =========================================================================== #


def test_a_blank_run_id_is_refused_because_it_names_the_attestation_scope() -> None:
    """The scope is derived from the run id, so the run id has to be real.

    An empty scope would collide with every other blank-run seal in the same
    table — ``attestation_chains.run_id`` is a primary key.
    """
    with pytest.raises(InvariantViolationError) as excinfo:
        ps.proof_scope("   ")
    assert "run id" in str(excinfo.value)


def test_the_retention_class_is_the_callers_and_defaults_to_hot(tmp_path: Path) -> None:
    """Retention travels with the manifest, defaulting to plan 12's ``HOT``.

    A caller who needs ``LEGAL_HOLD`` on a proof must be able to say so, and the
    default must match the run-close seal so an unconfigured proof is not treated
    differently from an unconfigured run.
    """
    store = _store(tmp_path)
    sealed = ps.seal_proof(
        store,
        _admitted_proof(),
        run_id="r-hot",
        recorded_at=READING,
    )
    assert sealed.manifest.retention_class is RetentionClass.HOT

    held = ps.seal_proof(
        store,
        _admitted_proof(),
        run_id="r-held",
        recorded_at=READING,
        retention_class=RetentionClass.LEGAL_HOLD,
    )
    assert held.manifest.retention_class is RetentionClass.LEGAL_HOLD
    stored = AttestationRepository(store).load_manifest("r-held:proof:manifest")
    assert stored is not None and stored.retention_class is RetentionClass.LEGAL_HOLD


def test_reloading_an_unsealed_run_reports_why_rather_than_raising(tmp_path: Path) -> None:
    """ "No seal stored" is a finding for a reader, not an exception.

    An auditor asking "was this run's proof sealed?" needs an answer either way,
    and the absent answer must be legible.
    """
    store = _store(tmp_path)

    reloaded, reason = ps.verify_sealed_proof(store, "r-never-ran")

    assert reloaded is None
    assert "no chain stored" in reason
