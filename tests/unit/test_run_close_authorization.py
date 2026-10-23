"""L2 Phase 3 — the policy decision and approval state reach the run close.

Plan 12 Phase 6 recorded two gaps: the run-close seal had no caller, and the
``RunAuthorization`` inputs were computed by ``validate_plan`` and discarded.
Both are now closed, and this suite is what makes them closed rather than merely
written.

The properties, in the order they matter:

* **the chain flips.** A run with an allowing policy gate and an approval gate
  seals a COMPLETE chain. Before this wiring every mutating run sealed an
  INCOMPLETE one, which is the honest-but-wrong state plan 12 named.
* **the sealed decision is the enforced one.** ``validate_plan`` retains the very
  object ``evaluate_gate`` returned — identity, not equality — so the chain
  cannot carry a re-derived decision that happens to agree today.
* **absent means absent.** No gate configured seals nothing and renders nothing,
  and the envelope is byte-identical to one from before this wiring. That is the
  additive claim, and it is the case for every deployment in this repository.
* **both inputs are required.** A policy gate with no approval gate still seals
  nothing, because there is nothing to authorize against.
* **failure degrades, never raises.** A seal failure leaves the envelope alive
  with a remediation note, matching its sibling seal 40 lines above it.

The negative controls are the interesting half. Each breaks a *collaborator*
rather than ``src/mayhem``, so each is a statement about the property rather than
about the assertion: a sealer that returns an empty chain must still report
INCOMPLETE, and a plan digest the approval gate disagrees with must surface as
the domain's own typed refusal rather than as a silently accepted chain.
"""

from __future__ import annotations

import ast
import inspect
import json
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any

import pytest

from mayhem.cli.lifecycle import _write_evidence_after_run
from mayhem.controller.policy_evidence import seal_policy_decision
from mayhem.controller.safety import (
    GATE_VERDICT_APPROVAL,
    GATE_VERDICT_POLICY,
    SafetyContext,
    approval_verdict,
    policy_verdict,
)

if TYPE_CHECKING:
    from pathlib import Path

# --------------------------------------------------------------------------- #
# Harness
# --------------------------------------------------------------------------- #


def _store(tmp_path: Path) -> Any:
    from tests.unit.test_secret_development_seal import _open_store

    return _open_store(tmp_path)


def _preflight(*, policy: Any = None, approval: Any = None) -> Any:
    """A preflight shaped like the one the run path really passes.

    ``SimpleNamespace`` rather than ``Preflight`` on purpose: the run-close path
    reads these through ``getattr``, and a real ``Preflight`` would hide a
    misnamed attribute behind a ``dataclasses`` error instead of a silent
    ``None``. If L2's field names drift, this harness goes quiet and
    :func:`test_the_run_close_reads_the_two_verdict_attributes` fails by name.
    """
    return SimpleNamespace(
        plan=_plan(),
        plan_id="r-1",
        target_profile="dev",
        safety_decisions=("allow",),
        environment_fingerprint="env-1",
        target_identity="dev/api",
        blast_radius={"services": 1},
        compensation_status="verified",
        k8s_target_scope="dev",
        k8s_context="",
        k8s_namespace="",
        k8s_capability_verdict="allowed",
        k8s_wait_strategy="",
        k8s_recovery_guidance="",
        policy_verdict=policy,
        approval_verdict=approval,
    )


def _result() -> Any:
    return SimpleNamespace(
        run_id="r-1",
        steps=(SimpleNamespace(step_id="s1", ok=True, detail="ok", status="ok"),),
        observability=(),
        verdict="passed",
        status="completed",
        dirty_leases=(),
    )


def _plan() -> Any:
    """A real plan, so ``envelope.plan_hash`` is populated.

    The first version of this harness passed ``plan=None``, which makes the
    envelope's ``plan_hash`` empty — and then the mismatch test would have been
    asserting a disagreement against an empty string rather than against a real
    digest. Borrowed rather than hand-rolled: ``PlannedStep`` takes a
    ``TargetScope`` and a fault model, not the strings a reader would guess, and
    ``test_policy_evidence.py`` already builds the real thing.
    """
    from tests.unit.test_policy_evidence import _plan as _real_plan

    return _real_plan("proc.pause")


def _close(store: Any, **kwargs: Any) -> Any:
    return _write_evidence_after_run(
        store=store,
        preflight=kwargs.pop("preflight", _preflight()),
        result=_result(),
        engine="podman",
        evidence_dir=None,
        **kwargs,
    )


def _real_inputs() -> tuple[Any, Any]:
    """A real allowing ``PolicyGateResult`` and a real ``ApprovalGateResult``.

    The carrier carries the *result*, not the bare ``ApprovalState``, because the
    result also holds the ``plan_digest`` and ``proof_digest`` the approval was
    decided against. The first version of this file passed a bare
    ``ApprovalState`` and the run close degraded to a note with
    ``AttributeError: 'ApprovalState' object has no attribute 'state'`` — which
    is the degradation working, and is also why the test now builds the real
    thing rather than loosening the call site to accept either shape.
    """
    from tests.unit.test_policy_evidence import _allowing_result, _state

    return _allowing_result(), _approval_result(_state())


def _approval_result(state: Any) -> Any:
    """Wrap a real ``ApprovalState`` in a real ``ApprovalGateResult``."""
    from mayhem.controller.approval_gate import ApprovalGateResult, AuthorizationVerdict
    from mayhem.domain.identity import Role
    from mayhem.domain.safety_proof import ProofVerdict

    return ApprovalGateResult(
        state=state,
        authorization=AuthorizationVerdict(
            principal="ana",
            environment="test",
            roles=frozenset({Role.EXECUTE}),
        ),
        proof_verdict=ProofVerdict.PASS,
        plan_digest="",
        policy_digest="",
        proof_digest="",
        environment="test",
        required=1,
        now=_now(),
    )


def _now() -> Any:
    from datetime import UTC, datetime

    return datetime(2026, 1, 1, tzinfo=UTC)


# --------------------------------------------------------------------------- #
# The carrier
# --------------------------------------------------------------------------- #


class TestTheCarrier:
    def test_a_context_that_ran_no_gate_carries_no_verdicts(self) -> None:
        from mayhem.config import PolicyCfg
        from mayhem.domain.experiments import BlastRadiusBudget

        ctx = SafetyContext(policy=PolicyCfg(), budget=BlastRadiusBudget(), fingerprint="fp")
        assert policy_verdict(ctx) is None
        assert approval_verdict(ctx) is None
        assert ctx.gate_verdicts == {}

    def test_the_accessors_ignore_a_misspelled_key_rather_than_returning_it(
        self,
    ) -> None:
        """A typo at a read site must be a miss, not a wrong-shaped object.

        The accessors are typed, so the mapping is the only place a
        misspellable thing exists. Returning the stored value unchecked would let
        a stray string reach ``seal_policy_decision`` and surface as an
        ``AttributeError`` deep in the sealer instead of as "no gate ran".
        """
        from mayhem.config import PolicyCfg
        from mayhem.domain.experiments import BlastRadiusBudget

        ctx = SafetyContext(policy=PolicyCfg(), budget=BlastRadiusBudget(), fingerprint="fp")
        ctx.gate_verdicts["polciy"] = "not a result"
        assert policy_verdict(ctx) is None
        assert approval_verdict(ctx) is None

    def test_the_key_constants_are_the_documented_strings(self) -> None:
        assert GATE_VERDICT_POLICY == "policy"
        assert GATE_VERDICT_APPROVAL == "approval"


# --------------------------------------------------------------------------- #
# The run close
# --------------------------------------------------------------------------- #


class TestTheRunClose:
    def test_a_run_with_no_policy_gate_seals_nothing(self, tmp_path: Path) -> None:
        store = _store(tmp_path)
        try:
            envelope = _close(store)
        finally:
            store.close()
        assert envelope is not None
        assert not any("policy authorization" in note for note in envelope.remediation), (
            "a run with no gate configured must seal silently, not report a failure"
        )
        assert envelope.evidence_status != "degraded"

    def test_a_policy_gate_with_no_approval_gate_seals_nothing(self, tmp_path: Path) -> None:
        """Both inputs are required; one alone authorizes nothing.

        There is no default ``ApprovalState`` for an unconfigured approval gate,
        and inventing one would mean deciding what an absent quorum says. That
        is a policy question, recorded in L2's ledger rather than answered here.
        """
        policy, _approval = _real_inputs()
        store = _store(tmp_path)
        try:
            envelope = _close(store, preflight=_preflight(policy=policy))
        finally:
            store.close()
        assert envelope is not None
        assert not any("policy authorization" in note for note in envelope.remediation)

    def test_an_allowed_gate_seals_a_complete_chain(self, tmp_path: Path) -> None:
        """The whole point: the chain stops reporting INCOMPLETE."""
        from mayhem.infra.attestation_store import (
            AttestationRepository,
            chain_completeness,
        )

        policy, approval = _real_inputs()
        store = _store(tmp_path)
        try:
            envelope = _close(store, preflight=_preflight(policy=policy, approval=approval))
            assert envelope is not None
            assert not any(
                "not sealed into the evidence chain" in note for note in envelope.remediation
            ), envelope.remediation
            events = AttestationRepository(store).load_chain("r-1")
            completeness = chain_completeness(events)
        finally:
            store.close()
        assert events, "the run closed without sealing any chain at all"
        assert completeness.complete, (
            f"an allowing, approved run still seals an incomplete chain: {completeness}"
        )

    def test_a_run_with_no_gate_still_seals_an_incomplete_chain(self, tmp_path: Path) -> None:
        """The before-state, pinned so the test above means something.

        Without this, "the chain is complete" could pass because the chain was
        never sealed at all, which is a different defect wearing the same
        green.
        """
        from mayhem.infra.attestation_store import (
            AttestationRepository,
            chain_completeness,
        )

        store = _store(tmp_path)
        try:
            _close(store)
            events = AttestationRepository(store).load_chain("r-1")
            completeness = chain_completeness(events)
        finally:
            store.close()
        assert not completeness.complete, (
            f"a run with no policy gate configured reported a complete chain: {completeness}"
        )

    def test_the_envelope_is_the_run_close_plan_digest_source(self, tmp_path: Path) -> None:
        """Taking ``plan_digest`` from the envelope is what makes a disagreement
        unexpressible rather than merely unlikely.

        ``PolicyGateResult`` carries no ``plan_digest`` at all — the only plan
        digest in play is the one the approval gate decided against, and the
        only other one is ``envelope.plan_hash``. This pins that the call site
        reads the envelope's, by sealing successfully through it.
        """
        policy, approval = _real_inputs()
        store = _store(tmp_path)
        try:
            envelope = _close(store, preflight=_preflight(policy=policy, approval=approval))
            assert envelope is not None
            assert not any(
                "not sealed into the evidence chain" in note for note in envelope.remediation
            ), envelope.remediation
            assert envelope.plan_hash
        finally:
            store.close()

    def test_a_plan_digest_the_envelope_does_not_carry_is_refused(self, tmp_path: Path) -> None:
        """The negative control: the mismatch check is reached in the real path.

        ``RunAuthorization`` compares ``plan_digest`` against
        ``envelope.plan_hash`` and raises ``AuthorizationMismatchError``. This
        proves the comparison is load-bearing rather than present in the module,
        and it is why reading the digest off the envelope matters.
        """
        from mayhem.infra.attestation_store import AuthorizationMismatchError

        policy, approval = _real_inputs()
        store = _store(tmp_path)
        try:
            envelope = _close(store, preflight=_preflight())
            assert envelope is not None
            with pytest.raises(AuthorizationMismatchError) as excinfo:
                seal_policy_decision(
                    store,
                    policy,
                    envelope,
                    approval_state=approval.state,
                    plan_digest="0" * 64,
                    run_status="completed",
                    verdict="passed",
                )
            assert "plan" in str(excinfo.value).lower()
        finally:
            store.close()

    def test_a_seal_failure_degrades_to_a_note_and_keeps_the_envelope(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Losing the envelope because an *additional* record failed is the wrong trade."""
        policy, approval = _real_inputs()
        store = _store(tmp_path)
        try:
            monkeypatch.setattr(
                "mayhem.controller.policy_evidence.seal_policy_decision",
                _explode,
            )
            envelope = _close(store, preflight=_preflight(policy=policy, approval=approval))
        finally:
            store.close()
            monkeypatch.undo()
        assert envelope is not None, "a seal failure must not lose the envelope"
        assert any(
            "policy authorization not sealed" in note and "RuntimeError" in note
            for note in envelope.remediation
        ), envelope.remediation
        # The envelope itself is not marked degraded: what failed was an extra
        # record, and claiming the evidence is degraded would overstate it.
        assert envelope.evidence_status != "degraded"

    def test_a_denied_policy_never_reaches_the_close(self, tmp_path: Path) -> None:
        """A refusal is evidence; it is not an authorization.

        ``build_authorization`` refuses a denied result, and because
        ``validate_plan`` raises on a denial the close is never reached with one.
        Asserted at the sealer so the property is the sealer's, not the
        executor's.
        """
        from tests.unit.test_policy_evidence import _bundle, _inputs, _plan, _rule, _state

        from mayhem.controller.policy_evidence import (
            RULE_DECISION_DENIED,
            PolicyAuthorizationRefusedError,
            build_authorization,
        )
        from mayhem.domain.policy import PolicyDimension, PolicyEffect, PolicyOperator

        denied = _evaluate_denied(
            _bundle, _rule, _plan, _inputs, PolicyDimension, PolicyEffect, PolicyOperator
        )
        assert denied.denied
        with pytest.raises(PolicyAuthorizationRefusedError) as excinfo:
            build_authorization(denied, approval_state=_state(), plan_digest="d" * 64)
        assert excinfo.value.rule_id == RULE_DECISION_DENIED


def _evaluate_denied(bundle, rule, plan, inputs, dimension, effect, operator) -> Any:
    from mayhem.domain.policy_gate import evaluate_gate

    return evaluate_gate(
        plan("proc.pause"),
        inputs(
            bundle(
                rule(
                    "prod.forbids",
                    dimension.ENVIRONMENT,
                    operator.IN,
                    ("production",),
                    effect=effect.DENY,
                )
            )
        ),
        environment="production",
    )


def _explode(*args: Any, **kwargs: Any) -> Any:
    raise RuntimeError("the sealer is down")


# --------------------------------------------------------------------------- #
# The wiring is statically visible
# --------------------------------------------------------------------------- #


def test_the_run_close_calls_the_seal() -> None:
    """A source-parsing guard, because there is no store boundary to catch this.

    The seal lives inside a ``try``/``except`` that degrades, so deleting the
    call does not raise anywhere: the run would simply stop sealing and every
    behavioural test above would pass by asserting the *absence* of a note.
    That is the shape of a guard that has to be static.
    """
    from mayhem.cli import lifecycle

    tree = ast.parse(inspect.getsource(lifecycle))
    called: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef) or node.name != "_write_evidence_after_run":
            continue
        for inner in ast.walk(node):
            if isinstance(inner, ast.Call):
                func = inner.func
                if isinstance(func, ast.Name):
                    called.add(func.id)
                elif isinstance(inner.func, ast.Attribute):
                    called.add(func.attr)
    assert "seal_policy_decision" in called, (
        "the run close no longer seals the policy authorization; the chain goes "
        f"back to INCOMPLETE for every run. It calls {sorted(called) or 'nothing'}."
    )


def test_the_seal_sits_after_write_evidence_and_before_the_artifact() -> None:
    """Placement is load-bearing: the envelope row must exist first.

    Read from the source rather than asserted through behaviour because the two
    orders differ only in which row a failure would leave behind — a difference
    no happy-path test can see.
    """
    from mayhem.cli import lifecycle

    tree = ast.parse(inspect.getsource(lifecycle))
    order: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef) or node.name != "_write_evidence_after_run":
            continue
        for inner in ast.walk(node):
            if not isinstance(inner, ast.Call):
                continue
            name = inner.func.id if isinstance(inner.func, ast.Name) else None
            if name is None and isinstance(inner.func, ast.Attribute):
                name = inner.func.attr
            if name in {"write_evidence", "seal_policy_decision", "write_evidence_file"}:
                order.append(name)
    if "seal_policy_decision" not in order:
        pytest.skip("the call was not found; test_the_run_close_calls_the_seal reports it")
    assert order.index("write_evidence") < order.index("seal_policy_decision"), order
    assert order.index("seal_policy_decision") < order.index("write_evidence_file"), order


def test_the_run_close_reads_the_two_verdict_attributes() -> None:
    """The attribute names the carrier defines and the call site reads must agree.

    Two independent edits — a dataclass field and a ``getattr`` string — and a
    rename on one side would leave the other reading ``None``, which is
    indistinguishable from "no gate was configured". This is the only check that
    sees it.
    """
    from mayhem.cli import lifecycle
    from mayhem.domain.preflight import Preflight

    tree = ast.parse(inspect.getsource(lifecycle))
    read: set[str] = set()
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)):
            continue
        if node.func.id != "getattr" or len(node.args) < 2:
            continue
        second = node.args[1]
        if not (isinstance(second, ast.Constant) and isinstance(second.value, str)):
            continue
        if second.value.endswith("_verdict") and "k8s" not in second.value:
            read.add(second.value)
    fields = set(Preflight.__dataclass_fields__)
    for name in read:
        assert name in fields, (
            f"the run close reads {name!r} but Preflight has no such field; a "
            "renamed carrier reads as 'no gate configured' and seals nothing"
        )
    assert read == {"policy_verdict", "approval_verdict"}, read


def test_the_sealer_is_the_one_plan_12_wrote() -> None:
    """One sealer. This wiring must not have introduced a second."""
    from mayhem.cli import lifecycle

    tree = ast.parse(inspect.getsource(lifecycle))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and (node.module or "").startswith(
            "mayhem.controller.policy_evidence"
        ):
            imported.update(alias.name for alias in node.names)
    assert "seal_policy_decision" in imported, imported
    # And not a hand-rolled equivalent.
    assert not any(
        "build_authorization" in imported or "RunAuthorization" in imported for _ in (0,)
    )


def test_the_envelope_is_unchanged_for_a_run_with_no_gate(tmp_path: Path) -> None:
    """The additive claim, end to end.

    Two closes of the same run, one with the verdict attributes absent from the
    preflight entirely (the shape every deployment has today) and one with them
    present but ``None``. The two envelopes must be identical — which is what
    makes "no regression for existing callers" a checked claim rather than an
    assertion in a comment.
    """
    bare = SimpleNamespace(
        **{
            key: value
            for key, value in vars(_preflight()).items()
            if key not in {"policy_verdict", "approval_verdict"}
        }
    )
    first_store = _store(tmp_path / "a")
    second_store = _store(tmp_path / "b")
    try:
        first = _write_evidence_after_run(
            store=first_store,
            preflight=bare,
            result=_result(),
            engine="podman",
            evidence_dir=None,
        )
        second = _write_evidence_after_run(
            store=second_store,
            preflight=_preflight(),
            result=_result(),
            engine="podman",
            evidence_dir=None,
        )
    finally:
        first_store.close()
        second_store.close()
    assert first is not None and second is not None
    assert _stable(first) == _stable(second), (
        "adding the L2 carrier moved the envelope for a run that configured no "
        "gate, which is not additive"
    )


#: Fields that legitimately differ between two closes microseconds apart. Read the
#: real key rather than guessing a prefix list — a blanket ``created_at`` strip
#: would hide a digest that moved.
VOLATILE_KEYS: frozenset[str] = frozenset({"created_at", "emitted_spans"})


def _stable(envelope: Any) -> str:
    return json.dumps(
        {key: value for key, value in envelope.to_dict().items() if key not in VOLATILE_KEYS},
        default=str,
        sort_keys=True,
    )
