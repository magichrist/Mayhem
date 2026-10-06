"""Plan 03 Phase 5: the fabric's protocol conformance suite.

Phase 5's named items, and where each one is answered:

* **Protocol conformance (malformed / replayed / forged commands).** The wire
  seam is :func:`~mayhem.controller.fabric_evidence.decode_wire_command` — the
  only place an envelope arrives as untrusted bytes — plus the domain's own
  refusal functions. The suite drives frames a hostile peer would send: a body
  forged after signing, a frame with no signature at all, frames missing each
  kind of required field, and bytes that are not JSON at all. Each gets one
  refusal code, and the two codes stay distinct: *the signature did not verify*
  is never spent on *a field is missing*.
* **Failover drills.** :mod:`tests.unit.test_fabric_engine` drills a killed
  controller over an in-memory journal; :mod:`tests.unit.test_fabric_evidence`
  drills the durable resume. The drills here run the chain **with plan 19's
  verifier bound on every controller** — the spelling a real deployment runs —
  and re-assert that a failover chain cannot double-execute and that a deposed
  owner is refused with its session untouched.
* **Provider-error normalization matrix.** Every code in
  ``DRIFT_ERROR_CODES`` / ``CONFLICT_ERROR_CODES`` is driven through
  :func:`~mayhem.controller.fabric_engine.normalise_provider_result`, the
  agent-refusal table is driven end to end, and drift is shown outranking the
  provider's own verdict — then sealed into evidence under
  :data:`~mayhem.controller.fabric_evidence.EVENT_FABRIC_DRIFT`.
* **Orchestration-semantics negative controls.** Honest about the layer:
  ``StepSemantics`` is *planner-level vocabulary* by this plan's own text
  ("not provider behavior"), so the controls live where the types live — an
  unbounded ``loop`` and a targetless ``branch`` are unconstructible, caps are
  total, and the engine carries no interpreter for them at all (asserted
  structurally, so an interpreter cannot appear without this suite failing).
* **Negative control the plan names by sentence:** "an agent that accepts an
  unsigned command fails the suite loudly". There is no code path from an
  unsigned frame to a constructible envelope; every spelling is refused, and
  the verifier-bound engine never reaches a provider on a forged signature.
* **Acceptance: live cells in plan 01 for the local providers.** The podman
  cell was certified live through ``mayhem certify run`` (sealed chain, recovery
  verified, residue clean) and re-verified by ``certify regress --rerun``. This
  suite reads that record through the store and is a real assertion when the
  record exists — skipped, with the command that produces it, when it does not.
  Local providers means what it says: the podman cell on darwin/arm64/rootless.
  Docker and Kubernetes cells have never been certified, and this file does not
  pretend otherwise.
"""

from __future__ import annotations

import inspect
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from pydantic import ValidationError

import mayhem.controller.fabric_engine as fabric_engine_module
from mayhem.controller.fabric_engine import (
    _REFUSAL_OUTCOMES,
    CONFLICT_ERROR_CODES,
    DRIFT_ERROR_CODES,
    FABRIC_MALFORMED_ENVELOPE,
    DispatchRequest,
    FabricEngine,
    ProviderResult,
    _normalise_refusal,
    normalise_provider_result,
)
from mayhem.controller.fabric_evidence import (
    EVENT_FABRIC_DISPATCHED,
    EVENT_FABRIC_DRIFT,
    FabricEvidenceRecorder,
    decode_wire_command,
    fabric_timeline,
    load_fabric_chain,
    verify_dispatch_command,
)
from mayhem.domain.agent_identity import (
    AgentCredential,
    AgentIdentity,
    CertificateRef,
    TrustAnchorRef,
)
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.fabric import (
    FABRIC_PROTOCOL_VERSION,
    FABRIC_REPLAYED_NONCE,
    FABRIC_STALE_FENCE,
    FABRIC_UNDERSIGNED,
    CommandBodyRef,
    FabricCommand,
    FabricCommandRefused,
    FabricCommandType,
    FencingToken,
    NonceLedger,
    StepSemantics,
    StepSpec,
    assert_fence_current,
)
from mayhem.domain.hashing import sha256_hex
from mayhem.domain.identity import EnvironmentScope, Principal, PrincipalKind
from mayhem.domain.leases import FaultLease, LeaseState, UndoOp, VerifyProbe
from mayhem.domain.outcomes import StepOutcome, TargetOutcome
from mayhem.infra.agent_identity_store import AgentIdentityRepository
from mayhem.infra.agent_identity_verifier import (
    AgentCommandVerifier,
    HmacSha256CommandSigner,
    HmacSha256SignatureVerifier,
    SqliteNonceLedger,
    StaticKeyMaterial,
)
from mayhem.infra.certification_repository import CertificationRepository
from mayhem.infra.lease_repository import SQLiteLeaseSink
from mayhem.infra.store import Store

if TYPE_CHECKING:
    from collections.abc import Callable

RUN_ID = "r-fabric-conf"
STEP_ID = "s-1"
AGENT = "ag-1"
CONTROLLER = "ctl-a"
CREDENTIAL = "cr-1"
SECRET = b"c" * 32
PLAN = sha256_hex('{"steps":["inject"]}')
OTHER_PLAN = sha256_hex('{"steps":["inject","compensate"]}')
BODY_DIGEST = "b" * 64
TARGET = "pod/web-0"
OTHER_TARGET = "pod/web-1"
CERT_FINGERPRINT = "f" * 64

NOW = datetime(2026, 3, 6, 4, 5, 6, tzinfo=UTC)

#: The record `mayhem certify run` minted live on this machine. The acceptance
#: line this suite checks against; skipped honestly where it does not exist.
LIVE_CERT_DB = Path("/tmp/cert-live3.db")


# --------------------------------------------------------------------------- #
# Builders                                                                     #
# --------------------------------------------------------------------------- #


class _Clock:
    def __init__(self, moment: datetime = NOW) -> None:
        self.moment = moment

    def __call__(self) -> datetime:
        return self.moment

    def advance(self, seconds: float) -> None:
        self.moment = self.moment + timedelta(seconds=seconds)


def keys(*secrets: tuple[str, bytes]) -> StaticKeyMaterial:
    material = StaticKeyMaterial()
    for key_id, secret in secrets or ((CREDENTIAL, SECRET),):
        material.add(key_id, secret)
    return material


def _credential() -> AgentCredential:
    return AgentCredential(
        credential_id=CREDENTIAL,
        agent_id=AGENT,
        issued_at=NOW - timedelta(seconds=60),
        expires_at=NOW + timedelta(seconds=900),
        rotate_before=300.0,
    )


def _certificate() -> CertificateRef:
    return CertificateRef(
        subject=f"agent={AGENT}",
        issuer="ca-mesh-1",
        serial="01",
        sha256_fingerprint=CERT_FINGERPRINT,
        not_before=NOW - timedelta(hours=1),
        not_after=NOW + timedelta(hours=1),
    )


def _identity() -> AgentIdentity:
    return AgentIdentity(
        agent_id=AGENT,
        controller_id=CONTROLLER,
        principal=Principal(principal_id="sa-agent-1", kind=PrincipalKind.WORKLOAD),
        scope=EnvironmentScope(environment="staging"),
        credential=_credential(),
        certificate=_certificate(),
        trust_anchors=(
            TrustAnchorRef(
                ca_id="ca-mesh-1",
                subject="ca-mesh-1",
                sha256_fingerprint=CERT_FINGERPRINT,
            ),
        ),
    )


def _fence(epoch: int = 1, *, holder: str = "agent-1", step_id: str = STEP_ID) -> FencingToken:
    return FencingToken(
        run_id=RUN_ID,
        step_id=step_id,
        holder=holder,
        epoch=epoch,
        issued_at=NOW,
        supersedes_epoch=epoch - 1 if epoch > 1 else None,
    )


def _command_fields(
    *,
    nonce: int = 1,
    epoch: int = 1,
    command_id: str = "fc-1",
    idempotency_key: str = "idem-1",
    plan_digest: str = PLAN,
    step_id: str = STEP_ID,
    holder: str = "agent-1",
    signing_key_id: str = CREDENTIAL,
    body_digest: str = BODY_DIGEST,
) -> dict[str, object]:
    """An *unsigned* field mapping. ``signature`` is deliberately absent."""
    return {
        "protocol": FABRIC_PROTOCOL_VERSION,
        "command_id": command_id,
        "run_id": RUN_ID,
        "step_id": step_id,
        "agent_id": AGENT,
        "plan_digest": plan_digest,
        "nonce": f"{nonce:032x}",
        "idempotency_key": idempotency_key,
        "fencing_token": _fence(epoch, holder=holder, step_id=step_id).model_dump(mode="json"),
        "command": CommandBodyRef(
            command_type=FabricCommandType.INJECT,
            body_digest=body_digest,
            body_ref="blob-1",
        ).model_dump(mode="json"),
        "issued_at": NOW.isoformat(),
        "signing_key_id": signing_key_id,
    }


def sign(material: StaticKeyMaterial | None = None, **overrides: object) -> FabricCommand:
    """Mint a validly signed envelope under the identity's current credential."""
    fields = _command_fields(**overrides)  # type: ignore[arg-type]
    return HmacSha256CommandSigner(material if material is not None else keys()).sign_fields(fields)


def forge(command: FabricCommand, **changes: object) -> FabricCommand:
    """A well-formed envelope whose bytes changed after signing."""
    return FabricCommand.model_validate({**command.model_dump(), **changes})


def _step(step_id: str = STEP_ID, semantic: StepSemantics = StepSemantics.SERIAL) -> StepSpec:
    return StepSpec(step_id=step_id, semantic=semantic, issued_at=NOW)


def _request(command: FabricCommand | None = None, **overrides: object) -> DispatchRequest:
    envelope = command if command is not None else sign()
    fields: dict[str, object] = {
        "step": _step(envelope.step_id),
        "command": envelope,
        "current_plan_digest": PLAN,
        "expected_target": TARGET,
    }
    fields.update(overrides)
    return DispatchRequest.model_validate(fields)


def _lease(lease_id: str = "l-1", *, owner: str = AGENT) -> FaultLease:
    return FaultLease(
        id=lease_id,
        run_id=RUN_ID,
        fault_id="net.latency",
        owner_agent=owner,
        targets=frozenset({TARGET}),
        undo_ops=(UndoOp(op="tc.qdisc_add", args={"if": "eth0"}),),
        verify_probes=(VerifyProbe(probe="tc.qdisc_absent", args={"if": "eth0"}),),
        state=LeaseState.ACTIVE,
        created_at=NOW,
    )


def _applied(lease: FaultLease | None = None, *, target: str = TARGET) -> ProviderResult:
    return ProviderResult(ok=True, detail="qdisc added", target_ref=target, lease=lease)


def _drifted() -> ProviderResult:
    return ProviderResult(ok=True, detail="qdisc added", target_ref=OTHER_TARGET)


def _failed(code: str | None = None, *, detail: str = "provider said no") -> ProviderResult:
    return ProviderResult(ok=False, detail=detail, target_ref=TARGET, error_code=code)


class ScriptedSession:
    """A controller-initiated session replaying a scripted provider."""

    def __init__(self, *results: ProviderResult | BaseException) -> None:
        self._queue: list[ProviderResult | BaseException] = list(results)
        self.calls: list[FabricCommand] = []

    def dispatch(self, command: FabricCommand) -> ProviderResult:
        self.calls.append(command)
        if not self._queue:
            raise AssertionError(f"provider was dispatched unexpectedly: {command.command_id}")
        nxt = self._queue.pop(0)
        if isinstance(nxt, BaseException):
            raise nxt
        return nxt


def _verifier(store: Store, *, enrol: bool = True) -> AgentCommandVerifier:
    """Plan 19's verifier over the real identity store and nonce ledger."""
    if enrol:
        AgentIdentityRepository(store).save(_identity())
    return AgentCommandVerifier(
        identities=AgentIdentityRepository(store),
        signature=HmacSha256SignatureVerifier(keys()),
        nonces=SqliteNonceLedger(store),
        controller_id=CONTROLLER,
    )


def _engine(
    store: Store,
    session: ScriptedSession,
    *,
    verifier: object | None = None,
    evidence: object | None = None,
    controller_id: str = CONTROLLER,
    clock: Callable[[], datetime] | None = None,
) -> FabricEngine:
    from mayhem.controller.fabric_evidence import SqliteFabricJournal

    fields: dict[str, object] = {
        "session": session,
        "journal": SqliteFabricJournal(store),
        "lease_sink": SQLiteLeaseSink(store),
        "controller_id": controller_id,
        "clock": clock or _Clock(),
    }
    if verifier is not None:
        fields["verifier"] = verifier
    if evidence is not None:
        fields["evidence"] = evidence
    return FabricEngine(**fields)  # type: ignore[arg-type]


@pytest.fixture
def store(tmp_path: Path):
    """A real migrated store — the production chain, unaltered."""
    opened = Store.open_migrated(tmp_path / "fabric-conf.db")
    try:
        yield opened
    finally:
        opened.close()


# --------------------------------------------------------------------------- #
# Protocol conformance: the frames a hostile peer sends                        #
# --------------------------------------------------------------------------- #


class TestWireConformance:
    def test_a_well_formed_signed_command_round_trips_through_the_wire(self) -> None:
        command = sign()
        decoded = decode_wire_command(command.model_dump_json())
        assert decoded == command
        assert decoded.protocol == FABRIC_PROTOCOL_VERSION == "mayhem/1"
        # The mapping form is the same envelope, not a second dialect.
        assert decode_wire_command(command.model_dump()) == command

    def test_a_body_forged_after_signing_decodes_but_does_not_verify(self, store: Store) -> None:
        """The wire seam checks the *envelope*; the verifier checks the *bytes*.

        Two seams, two questions, and a conformance suite has to keep them
        distinct: ``decode_wire_command`` accepts any well-formed envelope (a
        forged one is well-formed), and only the verifier — plan 19's, over the
        identity's current credential — catches that the body changed after
        signing with :data:`FABRIC_UNDERSIGNED`.
        """
        command = sign()
        assert command.step_id == STEP_ID
        forged = forge(command, step_id="s-evil")

        decoded = decode_wire_command(forged.model_dump_json())
        assert decoded.step_id == "s-evil", "well-formed forgery: the wire seam accepts it"

        with pytest.raises(FabricCommandRefused) as excinfo:
            verify_dispatch_command(forged, verifier=_verifier(store), now=NOW)

        assert excinfo.value.code == FABRIC_UNDERSIGNED

    def test_a_frame_without_a_signature_is_undersigned_never_malformed(self) -> None:
        """Missing signature is a *signature* fact, so it keeps that code.

        Spending ``fabric_malformed_envelope`` on a missing signature would
        answer "is this envelope intact?" with "no" while leaving "did anybody
        sign this?" unanswered — the ambiguity a conformance suite exists to
        pin down before an integrator guesses.
        """
        frame = _command_fields()
        assert "signature" not in frame
        for raw in (frame, json.dumps(frame), json.dumps(frame).encode()):
            with pytest.raises(FabricCommandRefused) as excinfo:
                decode_wire_command(raw)
            assert excinfo.value.code == FABRIC_UNDERSIGNED

    def test_a_frame_missing_any_other_required_field_is_malformed_and_names_it(
        self,
    ) -> None:
        for missing in ("nonce", "fencing_token", "command", "plan_digest", "issued_at"):
            frame = {k: v for k, v in _command_fields().items() if k != missing}
            frame["signature"] = "A" * 43
            with pytest.raises(FabricCommandRefused) as excinfo:
                decode_wire_command(frame)
            assert excinfo.value.code == FABRIC_MALFORMED_ENVELOPE
            assert any(missing in str(loc) for loc in excinfo.value.details["fields"]), (
                f"the refusal must name the missing field {missing!r}"
            )

    def test_bytes_that_are_not_a_frame_at_all_are_malformed(self) -> None:
        for raw in (b"", b"\x00\x01\x02", b"not-json", b"[]"):
            with pytest.raises(FabricCommandRefused) as excinfo:
                decode_wire_command(raw)
            assert excinfo.value.code == FABRIC_MALFORMED_ENVELOPE

    def test_a_replayed_nonce_is_unrepresentable_in_one_ledger(self) -> None:
        command = sign()
        ledger = NonceLedger().accept(command)
        assert ledger.knows(command.nonce)

        with pytest.raises(FabricCommandRefused) as excinfo:
            ledger.accept(sign(command_id="fc-replay"))  # fresh command_id, spent nonce

        assert excinfo.value.code == FABRIC_REPLAYED_NONCE

    def test_a_deposed_fence_is_refused_by_the_domain_predicate(self) -> None:
        served = _fence(epoch=2)
        command = sign(epoch=1)

        with pytest.raises(FabricCommandRefused) as excinfo:
            assert_fence_current(command, served_fence=served)

        assert excinfo.value.code == FABRIC_STALE_FENCE


class TestTheConformanceNegativeControl:
    """The plan's own sentence: an agent that accepts an unsigned command fails loudly."""

    def test_no_spelling_of_an_unsigned_command_constructs_an_envelope(self) -> None:
        unsigned = _command_fields()
        assert "signature" not in unsigned
        blanks = [
            {**unsigned, "signature": ""},
            {**unsigned, "signature": "   "},
            {**unsigned, "signature": "", "signing_key_id": ""},
        ]
        for frame in blanks:
            with pytest.raises(ValidationError):
                FabricCommand.model_validate(frame)
            with pytest.raises(FabricCommandRefused):
                decode_wire_command(frame)

    def test_a_verified_engine_never_reaches_a_provider_on_a_forged_signature(
        self, store: Store
    ) -> None:
        session = ScriptedSession(_applied())
        engine = _engine(store, session, verifier=_verifier(store))

        with pytest.raises(FabricCommandRefused) as excinfo:
            engine.dispatch(_request(forge(sign(), signature="A" * 43)))

        assert excinfo.value.code == FABRIC_UNDERSIGNED
        assert session.calls == [], "a forged envelope must never reach a provider"


# --------------------------------------------------------------------------- #
# Failover drills, with verification bound on every controller                 #
# --------------------------------------------------------------------------- #


class TestFailoverDrills:
    def test_a_failover_chain_cannot_double_execute_with_verification_enabled(
        self, store: Store
    ) -> None:
        session_a = ScriptedSession(_applied(lease=_lease("l-1")))
        engine_a = _engine(store, session_a, verifier=_verifier(store), evidence=None)
        first = engine_a.dispatch(_request())
        assert first.ok is True

        # ctl-b takes the step over at epoch 2, verified like every real command.
        session_b = ScriptedSession(_applied(lease=_lease("l-2")))
        engine_b = _engine(
            store, session_b, verifier=_verifier(store, enrol=False), controller_id="ctl-b"
        )
        second = engine_b.dispatch(
            _request(sign(nonce=2, epoch=2, command_id="fc-b", idempotency_key="idem-b"))
        )
        assert second.ok is True

        # ctl-a's late epoch-1 command is a deposed owner: refused by name, and
        # its session is never touched.
        late_session = ScriptedSession(_applied())
        late = _engine(store, late_session, verifier=_verifier(store, enrol=False))
        with pytest.raises(FabricCommandRefused) as excinfo:
            late.dispatch(_request(sign(nonce=3, command_id="fc-late")))

        assert excinfo.value.code == FABRIC_STALE_FENCE
        assert late_session.calls == []
        # Exactly two effects exist in the world, one per epoch: never two owners
        # executing the same step.
        assert sorted(lease.id for lease in SQLiteLeaseSink(store).active_leases()) == [
            "l-1",
            "l-2",
        ]

    def test_the_successor_inherits_the_ledger_the_fence_and_the_leases(self, store: Store) -> None:
        session_a = ScriptedSession(_applied(lease=_lease("l-1")))
        engine_a = _engine(store, session_a, verifier=_verifier(store))
        engine_a.dispatch(_request())
        del engine_a, session_a  # only the database remains

        successor = _engine(store, ScriptedSession(), controller_id="ctl-b")

        assert successor.served_fence(RUN_ID, STEP_ID) is not None
        assert successor.served_fence(RUN_ID, STEP_ID).epoch == 1  # type: ignore[union-attr]
        assert [claim.controller_id for claim in successor.claims(RUN_ID)] == [CONTROLLER]
        assert successor.unrecovered_steps(RUN_ID) == (STEP_ID,)
        assert [lease.id for lease in successor.unreconciled_leases(RUN_ID)] == []
        assert [lease.id for lease in SQLiteLeaseSink(store).active_leases()] == ["l-1"]


# --------------------------------------------------------------------------- #
# Provider-error normalization matrix                                          #
# --------------------------------------------------------------------------- #


class TestProviderErrorNormalisationMatrix:
    @pytest.mark.parametrize("code", sorted(DRIFT_ERROR_CODES))
    def test_every_declared_drift_code_normalises_to_drift(self, code: str) -> None:
        normalisation = normalise_provider_result(_failed(code), expected_target=TARGET)
        assert normalisation.outcome is StepOutcome.TARGET_DRIFT
        assert normalisation.target_outcome is TargetOutcome.TARGET_DRIFT

    @pytest.mark.parametrize("code", sorted(CONFLICT_ERROR_CODES))
    def test_every_declared_conflict_code_normalises_to_conflict(self, code: str) -> None:
        normalisation = normalise_provider_result(_failed(code), expected_target=TARGET)
        assert normalisation.outcome is StepOutcome.FAILED
        assert normalisation.target_outcome is TargetOutcome.RESOURCE_CONFLICT

    def test_drift_outranks_the_providers_own_verdict(self) -> None:
        normalisation = normalise_provider_result(_drifted(), expected_target=TARGET)
        assert normalisation.outcome is StepOutcome.TARGET_DRIFT
        assert "claimed ok=True" in normalisation.detail

    def test_agreeing_success_is_completed_and_ok(self) -> None:
        normalisation = normalise_provider_result(_applied(), expected_target=TARGET)
        assert normalisation.outcome is StepOutcome.COMPLETED
        assert normalisation.target_outcome is None

    def test_an_unknown_code_is_failed_to_apply_never_an_invented_category(self) -> None:
        normalisation = normalise_provider_result(
            _failed("warp_field_instability"), expected_target=TARGET
        )
        assert normalisation.outcome is StepOutcome.FAILED
        assert normalisation.target_outcome is TargetOutcome.FAILED_TO_APPLY

    def test_a_failure_with_no_code_at_all_is_still_failed_to_apply(self) -> None:
        normalisation = normalise_provider_result(
            ProviderResult(ok=False, detail="", target_ref=TARGET), expected_target=TARGET
        )
        assert normalisation.target_outcome is TargetOutcome.FAILED_TO_APPLY

    @pytest.mark.parametrize(("fabric_code", "expected"), sorted(_REFUSAL_OUTCOMES.items()))
    def test_every_agent_refusal_normalises_to_its_declared_outcome(
        self, fabric_code: str, expected: TargetOutcome
    ) -> None:
        normalisation = _normalise_refusal(FabricCommandRefused(fabric_code, "refused by agent"))
        assert normalisation.outcome is StepOutcome.FAILED
        assert normalisation.target_outcome is expected

    def test_a_drift_settles_and_is_sealed_under_its_own_kind(self, store: Store) -> None:
        session = ScriptedSession(_drifted())
        engine = _engine(
            store, session, verifier=_verifier(store), evidence=FabricEvidenceRecorder(store)
        )
        result = engine.dispatch(_request())
        assert result.is_drift is True and result.ok is False

        # The sealed chain carries the drift under its own kind — the same
        # spelling plan 03's evidence section documents.
        kinds = [event.event_kind for event in load_fabric_chain(store, RUN_ID)]
        assert kinds == [EVENT_FABRIC_DISPATCHED, EVENT_FABRIC_DRIFT]

        timeline = fabric_timeline(store, RUN_ID)
        assert timeline.verified is True
        assert timeline.settlements[0].outcome == StepOutcome.TARGET_DRIFT.value
        assert timeline.settlements[0].target_outcome == TargetOutcome.TARGET_DRIFT.value


# --------------------------------------------------------------------------- #
# Orchestration semantics: planner-level, by the plan's own text               #
# --------------------------------------------------------------------------- #


class TestOrchestrationSemantics:
    def test_a_loop_stops_at_its_bound(self) -> None:
        loop = StepSpec(
            step_id="s-loop",
            semantic=StepSemantics.LOOP,
            bound=3,
            budget_ref="budget/ci",
            issued_at=NOW,
        )
        assert loop.iteration_cap() == 3

    @pytest.mark.parametrize("semantic", sorted(StepSemantics))
    def test_the_iteration_cap_is_total_over_the_vocabulary(self, semantic: StepSemantics) -> None:
        #: The well-formedness table, restated as the fields each step must
        #: carry to construct at all — so the cap question is asked only of
        #: steps that are legal.
        well_formed: dict[StepSemantics, dict[str, object]] = {
            StepSemantics.SERIAL: {},
            StepSemantics.PARALLEL: {"fan_out_step_ids": ("s-a", "s-b")},
            StepSemantics.CONDITIONAL: {"condition_ref": "pred/x"},
            StepSemantics.LOOP: {"bound": 7, "budget_ref": "budget/ci"},
            StepSemantics.RETRY: {"retry_limit": 4, "backoff_ref": "backoff/exp"},
            StepSemantics.TIMEOUT: {"timeout_s": 5.0},
            StepSemantics.BRANCH: {
                "condition_ref": "pred/x",
                "branch_targets": ("s-a", "s-b"),
            },
            StepSemantics.JOIN: {"join_step_ids": ("s-a", "s-b")},
            StepSemantics.WAIT: {"wait_ref": "event/x", "timeout_s": 5.0},
            StepSemantics.APPROVAL: {"approval_ref": "appr/1"},
            StepSemantics.COMPENSATE: {
                "compensates_step_id": "s-1",
                "verify_probe_ref": "probe/baseline",
            },
        }
        step = StepSpec(step_id="s-x", semantic=semantic, issued_at=NOW, **well_formed[semantic])

        if semantic is StepSemantics.LOOP:
            assert step.iteration_cap() == 7
        elif semantic is StepSemantics.RETRY:
            assert step.iteration_cap() == 4
        else:
            assert step.iteration_cap() is None

    def test_an_unbounded_loop_is_unrepresentable(self) -> None:
        with pytest.raises(InvariantViolationError):
            StepSpec(step_id="s-loop", semantic=StepSemantics.LOOP, issued_at=NOW)

    def test_a_loop_without_a_budget_ref_is_unrepresentable(self) -> None:
        with pytest.raises(InvariantViolationError):
            StepSpec(
                step_id="s-loop",
                semantic=StepSemantics.LOOP,
                bound=3,
                issued_at=NOW,
            )

    def test_a_branch_without_targets_is_unrepresentable_but_a_formed_one_constructs(
        self,
    ) -> None:
        with pytest.raises(InvariantViolationError):
            StepSpec(step_id="s-branch", semantic=StepSemantics.BRANCH, issued_at=NOW)

        formed = StepSpec(
            step_id="s-branch",
            semantic=StepSemantics.BRANCH,
            condition_ref="pred/healthy",
            branch_targets=("s-a", "s-b"),
            issued_at=NOW,
        )
        assert formed.branch_targets == ("s-a", "s-b")

    def test_the_engine_carries_no_semantics_interpreter(self) -> None:
        """``StepSemantics`` is planner vocabulary, not engine behavior.

        The plan is explicit that gap 16's constructs are "planner-level types,
        not provider behavior". This is the structural form of that sentence:
        the dispatch engine's source may not name the semantics vocabulary at
        all, so an interpreter cannot quietly appear in it without this suite
        failing. A run-path enforcer for loop budgets belongs to the budget
        hierarchy (plans 13/22), wired where those plans say.
        """
        source = inspect.getsource(fabric_engine_module)
        assert "StepSemantics" not in source
        assert "branch_targets" not in source
        assert "budget_ref" not in source


# --------------------------------------------------------------------------- #
# Acceptance: live cells in plan 01 for the local providers                    #
# --------------------------------------------------------------------------- #


class TestLiveCellAcceptance:
    @pytest.mark.skipif(
        not LIVE_CERT_DB.exists(),
        reason=(
            "no live certification record on this machine; produce one with "
            "`mayhem certify run proc.pause --execute --engine podman --compose "
            "examples/testCase/docker-compose.yml --container testcase-api --db "
            "/tmp/cert-live3.db`"
        ),
    )
    def test_the_podman_cell_holds_a_standing_live_claim(self) -> None:
        """The acceptance line, read through the record store — not asserted."""
        from mayhem.domain.certification import expire_by_time
        from mayhem.domain.common import utc_now

        live_store = Store.open_migrated(LIVE_CERT_DB)
        try:
            records = CertificationRepository(live_store).all()
            standing = [
                stored
                for stored in records
                if expire_by_time(stored.record, now=utc_now()).grants_live_verification
            ]
            assert standing, "the live record holds no standing claim"
            assert {stored.record.fault_id for stored in standing} == {"proc.pause"}
            assert all(stored.record.cell.engine.value == "podman" for stored in standing)
            assert all(stored.record.evidence for stored in standing), (
                "a live claim must carry its sealed bundle reference"
            )
        finally:
            live_store.close()
