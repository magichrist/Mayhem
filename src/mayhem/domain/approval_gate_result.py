"""The approval gate's verdict value types.

These four frozen dataclasses are what :mod:`mayhem.controller.approval_gate`
*produces*, not how it decides: the verdict, what the executor holds and what
the gate needed them to hold (``AuthorizationVerdict``), an emergency override
that counted (``ApprovalOverride``), the first-fatal refusal
(``ApprovalRefusal``), and the whole result carried to the run close
(``ApprovalGateResult``).

They live in the domain because their consumers reach below the gate:
``Preflight.approval_verdict`` (``mayhem.domain.preflight``) rides the verdict
out to the run close, and plan 12's sealer binds it to evidence without
re-running the gate. A domain evidence carrier cannot annotate itself with a
controller type — the layering contract is enforced by lint-imports and pinned
by ``tests/unit/test_import_contracts.py`` — so the value types moved down and
the controller gate re-exports them under their historical names
(``mayhem.controller.approval_gate.ApprovalGateResult`` still resolves), the
same policy ``infra`` has followed for value types since the contracts went
green in the v1.1.0 program.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from mayhem.domain.hashing import canonical_json, sha256_hex
from mayhem.domain.identity import Role

if TYPE_CHECKING:
    from datetime import datetime

    from mayhem.domain.approval import ApprovalState, InvalidationReason
    from mayhem.domain.policy_gate import RequiredApproval
    from mayhem.domain.safety_proof import ProofVerdict

# =============================================================================
# Verdicts
# =============================================================================


@dataclass(frozen=True)
class AuthorizationVerdict:
    """What the executor holds, and what the gate needed them to hold.

    ``authorized`` is ``all(required ⊆ roles)`` — no hierarchy, no inheritance,
    no "admin implies execute". A role is a role, and the environment scope is
    the boundary (:func:`~mayhem.domain.identity.effective_roles`).
    """

    principal: str
    environment: str
    roles: frozenset[Role]
    required: tuple[Role, ...] = (Role.EXECUTE,)

    @property
    def authorized(self) -> bool:
        return all(role in self.roles for role in self.required)

    @property
    def missing(self) -> tuple[Role, ...]:
        return tuple(role for role in self.required if role not in self.roles)

    def describe(self) -> str:
        held = ", ".join(sorted(role.value for role in self.roles)) or "no roles"
        return (
            f"{self.principal} holds [{held}] in {self.environment}; "
            f"this gate requires {', '.join(role.value for role in self.required)}"
        )

    def evidence(self) -> dict[str, Any]:
        return {
            "principal": self.principal,
            "environment": self.environment,
            "roles": sorted(role.value for role in self.roles),
            "required": [role.value for role in self.required],
            "missing": [role.value for role in self.missing],
            "authorized": self.authorized,
        }


@dataclass(frozen=True)
class ApprovalOverride:
    """An emergency override that counted, and who pressed it.

    The override *executes* — the plan runs — and it pays for that by being
    impossible to read as an ordinary approval downstream: it is a named record
    on :attr:`ApprovalGateResult.overrides`, it gets its own decision rule in
    ``mayhem.controller.approval_gate`` (``RULE_APPROVAL_OVERRIDE``) rather
    than the allow rule, and its principal, reason, and the approval's own
    digest are inside the sealed evidence payload. Mandatory post-hoc review
    is Phase 4's evidence work; the obligation to *record* is the gate's,
    because an override nobody can reconstruct is an override nobody can
    review.
    """

    approval_id: str
    principal: str
    reason: str
    environment: str
    approval_digest: str

    def describe(self) -> str:
        return (
            f"emergency override by {self.principal} ({self.approval_id}) in "
            f"{self.environment}: {self.reason}"
        )

    def evidence(self) -> dict[str, str]:
        return {
            "approval_id": self.approval_id,
            "principal": self.principal,
            "reason": self.reason,
            "environment": self.environment,
            "approval_digest": self.approval_digest,
        }


@dataclass(frozen=True)
class ApprovalRefusal:
    """The first-fatal refusal, in the shape ``SafetyRefusedError`` records.

    ``triggers`` is every :class:`~mayhem.domain.approval.InvalidationReason`
    that fired, canonically ordered — the operator-facing "why" is enumerated,
    not truncated to the first thing that happened to be checked. It is the
    *union* of the gate-level triggers and the reasons the approval evaluation
    found, so a refusal never reports less than both halves know: an
    unauthorized executor who also holds no valid approval is told both, and a
    void proof is reported alongside the approvals that stopped matching it.
    The winning check is named by ``rule_id``; the triggers are everything, not
    only what the winner found.
    """

    rule_id: str
    reason: str
    remediation: str
    triggers: tuple[InvalidationReason, ...]
    inputs: dict[str, Any]


@dataclass(frozen=True)
class ApprovalGateResult:
    """The verdict plus everything it was reached through.

    Carried whole, like :class:`mayhem.domain.policy_gate.PolicyGateResult`,
    so a later phase can bind it to evidence without re-running the gate and
    hoping the inputs still agree.
    """

    state: ApprovalState
    authorization: AuthorizationVerdict
    proof_verdict: ProofVerdict
    plan_digest: str
    policy_digest: str
    proof_digest: str
    environment: str
    required: int
    now: datetime
    separation_of_duties: bool = False
    requirements: tuple[RequiredApproval, ...] = ()
    overrides: tuple[ApprovalOverride, ...] = ()
    refusal: ApprovalRefusal | None = None

    @property
    def allowed(self) -> bool:
        return self.refusal is None

    @property
    def denied(self) -> bool:
        return not self.allowed

    @property
    def overridden(self) -> bool:
        """True when at least one counted approval came through the override path."""
        return bool(self.overrides)

    @property
    def unbound_levels(self) -> tuple[str, ...]:
        """Approval levels the policy decision named and this gate cannot bind.

        Reported, not enforced — see the controller gate's
        ``quorum_from_requirements``. On an *allowed* result a non-empty tuple
        means "authorized on N signatures; which group gave them is not
        recorded", which is the honest reading.
        """
        return tuple(sorted({r.approval_level for r in self.requirements}))

    def evidence(self) -> dict[str, Any]:
        """The sealed record: the whole decision, plus a digest over it.

        ``sealed_digest`` is taken over every other key, so a reader can
        recompute it from the payload and tell whether the record was edited
        after the fact. The refusal (when there is one) is inside the payload
        too: a refusal is evidence as much as an authorization is.
        """
        payload: dict[str, Any] = {
            "allowed": self.allowed,
            "at": self.now.isoformat(),
            "plan_digest": self.plan_digest,
            "policy_digest": self.policy_digest,
            "proof_digest": self.proof_digest,
            "environment": self.environment,
            "proof_verdict": self.proof_verdict.value,
            "separation_of_duties": self.separation_of_duties,
            "authorization": self.authorization.evidence(),
            "approvals": {
                "approvers": list(self.state.approvers),
                "required": self.required,
                "quorum_met": self.state.quorum_met,
                "reasons": [reason.value for reason in self.state.reasons],
                "discarded": [
                    {
                        "approval_id": discarded.approval_id,
                        "approver": discarded.approver,
                        "reasons": [reason.value for reason in discarded.reasons],
                    }
                    for discarded in self.state.discarded
                ],
            },
            "unbound_levels": list(self.unbound_levels),
            "overrides": [override.evidence() for override in self.overrides],
            "refusal": None
            if self.refusal is None
            else {
                "rule_id": self.refusal.rule_id,
                "reason": self.refusal.reason,
                "triggers": [reason.value for reason in self.refusal.triggers],
            },
        }
        return {**payload, "sealed_digest": sha256_hex(canonical_json(payload))}

    def describe(self) -> str:
        if self.refusal is not None:
            triggers = ""
            if self.refusal.triggers:
                triggers = f" ({', '.join(reason.value for reason in self.refusal.triggers)})"
            return f"DENY {self.refusal.reason}{triggers}"
        if self.overridden:
            return f"OVERRIDE {self.state.describe()}: " + "; ".join(
                override.describe() for override in self.overrides
            )
        return f"ALLOW {self.state.describe()}"
