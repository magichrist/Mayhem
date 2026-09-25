"""``mayhem.domain.execution_intent`` — execution is an *approved* act (v0.9.0).

Before v0.9.0 typing ``mayhem run SPEC`` was enough to inject faults: the
command compiled a plan, printed a preflight, and executed it anyway. A
mistyped argument, a stale plan file, or a recovered terminal session could
all mutate a real target without anybody having approved *that* plan, on
*that* target, with *that* engine.

This module is the contract that closes that gap. An :class:`ExecutionIntent`
is the approval record: it names the plan it approves (``plan_hash``), where
the approval points (``engine``, ``target_identity``), the policy it was
granted under (``policy_id``, ``blast_radius``), who granted it (``actor``,
``approved_at``), and how long it stays valid (``expires_at``,
``break_glass``).

The gate is :func:`require_execution_intent`. It is deliberately a pure
function over plain values — no IO, no adapters, no CLI — so every mutating
surface (the run engine, the janitor, recovery, dependency installs) can
share one rule and one set of stable refusal codes:

* :data:`INTENT_REQUIRED` (``execution_intent_required``) — no intent and no
  explicit approval.
* :data:`APPROVAL_EXPIRED` (``approval_expired``) — the approval's own
  deadline has passed.
* :data:`INTENT_MISMATCH` (``execution_intent_mismatch``) — the approval is
  bound to a different plan, engine, or target than the one about to run.

Compatibility: the pre-v0.9.0 implicit path is still reachable, but only
through the documented escape hatch ``MAYHEM_ALLOW_IMPLICIT_EXECUTION=1``. The
domain never reads the environment itself — that lookup belongs to the
application layer (:func:`mayhem.cli.app.implicit_execution_allowed`), which
passes the answer in as ``allow_implicit``. The contract therefore stays a pure
value model plus a pure decision: same inputs, same refusal, on every host and
in every test, and a surface cannot skip approval by forgetting to ask.

This module imports nothing outside the domain layer and touches neither the
environment nor the filesystem. :class:`ExecutionPlan` hashing is delegated to
:func:`mayhem.domain.preflight.plan_hash_for` so the intent and the gate always
agree on what "this plan" means.
"""

from __future__ import annotations

import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from mayhem.domain.errors import DomainError

#: The documented escape hatch that restores the pre-v0.9.0 implicit-execution
#: behaviour. The *name* lives here (it is part of the documented contract);
#: reading it is the application layer's job — see
#: :func:`mayhem.cli.app.implicit_execution_allowed`.
IMPLICIT_EXECUTION_ENV = "MAYHEM_ALLOW_IMPLICIT_EXECUTION"

#: Stable refusal codes. Part of the CLI's error contract.
INTENT_REQUIRED = "execution_intent_required"
APPROVAL_EXPIRED = "approval_expired"
INTENT_MISMATCH = "execution_intent_mismatch"

#: How long a freshly minted approval stays valid unless told otherwise.
DEFAULT_APPROVAL_TTL_S = 900.0

_REMEDIATION = (
    "approve explicitly: re-run with the command's explicit approval flag "
    "(--execute / -y) so the plan is bound to an intent"
)


class ExecutionIntentRefused(DomainError):
    """A mutating act was attempted without a valid, matching intent.

    Attributes:
        code: One of :data:`INTENT_REQUIRED`, :data:`APPROVAL_EXPIRED`, or
            :data:`INTENT_MISMATCH`.
        details: Stable, secret-free context (action, field names, short ids).
        remediation: Human-readable next step.
    """

    def __init__(
        self,
        code: str,
        message: str,
        *,
        details: Mapping[str, Any] | None = None,
        remediation: str = _REMEDIATION,
    ) -> None:
        self.code = code
        self.details: dict[str, Any] = dict(details or {})
        self.remediation = remediation
        super().__init__(message)


@dataclass(frozen=True, slots=True)
class ExecutionIntent:
    """An approval to execute one specific plan, once, on one specific target.

    Attributes:
        plan_hash: Hash of the plan the approval is bound to. Required for the
            intent to authorize anything.
        engine: Engine the approval is bound to (``docker``/``podman``/
            ``kubernetes``).
        target_identity: Target profile / logical target the approval is bound
            to. Optional; empty means "not bound to a specific target".
        policy_id: Policy the approval was granted under.
        blast_radius: The blast radius reviewed at approval time.
        actor: Who approved it.
        approved_at: Epoch seconds the approval was granted.
        expires_at: Epoch seconds the approval lapses. ``None`` means "no
            expiry recorded" — the gate never invents one.
        break_glass: Set when the approval was granted through a break-glass
            path (e.g. ``--skip-gate``); recorded, never silently dropped.
    """

    plan_hash: str
    engine: str = ""
    target_identity: str = ""
    policy_id: str = ""
    blast_radius: dict[str, Any] = field(default_factory=dict)
    actor: str = ""
    approved_at: float = 0.0
    expires_at: float | None = None
    break_glass: bool = False

    def is_expired(self, now: float | None = None) -> bool:
        """True when this approval's own deadline has passed."""
        if self.expires_at is None:
            return False
        moment = time.time() if now is None else now
        return moment >= float(self.expires_at)

    def mismatches(
        self,
        *,
        plan_hash: str = "",
        engine: str = "",
        target_identity: str = "",
    ) -> tuple[str, ...]:
        """Names of the bindings that disagree with what is about to run.

        A binding is only compared when *both* sides state one: an intent that
        does not claim a target cannot be mismatched by a target change, and a
        caller that does not resolve a target cannot invalidate an intent that
        does. An intent with no ``plan_hash`` binds no plan and is always a
        mismatch — an approval that approves nothing authorizes nothing.
        """
        fields: list[str] = []
        if not self.plan_hash:
            fields.append("plan_hash")
        elif plan_hash and self.plan_hash != plan_hash:
            fields.append("plan_hash")
        if self.engine and engine and self.engine != engine:
            fields.append("engine")
        if self.target_identity and target_identity and self.target_identity != target_identity:
            fields.append("target_identity")
        return tuple(fields)

    def to_dict(self) -> dict[str, Any]:
        return {
            "plan_hash": self.plan_hash,
            "engine": self.engine,
            "target_identity": self.target_identity,
            "policy_id": self.policy_id,
            "blast_radius": dict(self.blast_radius),
            "actor": self.actor,
            "approved_at": self.approved_at,
            "expires_at": self.expires_at,
            "break_glass": self.break_glass,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ExecutionIntent:
        expires = data.get("expires_at")
        blast = data.get("blast_radius")
        return cls(
            plan_hash=str(data.get("plan_hash") or ""),
            engine=str(data.get("engine") or ""),
            target_identity=str(data.get("target_identity") or ""),
            policy_id=str(data.get("policy_id") or ""),
            blast_radius=dict(blast) if isinstance(blast, Mapping) else {},
            actor=str(data.get("actor") or ""),
            approved_at=float(data.get("approved_at") or 0.0),
            expires_at=None if expires is None else float(expires),
            break_glass=bool(data.get("break_glass", False)),
        )


def implicit_execution_requested(allow_implicit: bool | None) -> bool:
    """Normalize the caller's answer about the compatibility switch.

    ``None`` means "nobody said", which is a refusal: an approval is required
    unless the application layer positively reports the documented switch.
    Kept in the domain so the rule ("default is refuse") is stated once.
    """
    return allow_implicit is True


def require_execution_intent(
    intent: ExecutionIntent | None,
    *,
    plan_hash: str = "",
    engine: str = "",
    target_identity: str = "",
    action: str = "execute",
    allow_implicit: bool | None = None,
    now: float | None = None,
) -> ExecutionIntent | None:
    """Gate a mutating act behind an explicit, current, matching intent.

    Call this *immediately before* the first irreversible step — opening a
    run row, acquiring a lease, installing a package. Returns the validated
    intent, or ``None`` when execution proceeded through the compatibility
    switch the application layer reported via ``allow_implicit``.

    The function is pure: it reads no environment, opens no file, and calls no
    adapter. ``allow_implicit=None`` (the default) is a refusal, so a caller
    that forgets to ask still gets the safe answer.

    Raises:
        ExecutionIntentRefused: With code :data:`INTENT_REQUIRED` when there
            is no intent and no compatibility switch, :data:`APPROVAL_EXPIRED`
            when the approval has lapsed, or :data:`INTENT_MISMATCH` when the
            approval is bound to a different plan, engine, or target.
    """
    permitted = implicit_execution_requested(allow_implicit)
    if intent is None:
        if permitted:
            return None
        raise ExecutionIntentRefused(
            INTENT_REQUIRED,
            f"{action} refused: no explicit execution intent; "
            "execution is an approved act, not a side effect of the command",
            details={"action": action, "implicit_execution_env": IMPLICIT_EXECUTION_ENV},
        )
    moment = time.time() if now is None else now
    if intent.is_expired(moment):
        raise ExecutionIntentRefused(
            APPROVAL_EXPIRED,
            f"{action} refused: the execution intent approved by "
            f"{intent.actor or 'unknown actor'} expired at {intent.expires_at}",
            details={
                "action": action,
                "expires_at": intent.expires_at,
                "actor": intent.actor,
            },
            remediation="re-approve against the current plan and retry",
        )
    fields = intent.mismatches(
        plan_hash=plan_hash, engine=engine, target_identity=target_identity
    )
    if fields:
        raise ExecutionIntentRefused(
            INTENT_MISMATCH,
            f"{action} refused: the execution intent is bound to a different "
            f"{', '.join(fields)}; re-approve against what is about to run",
            details={
                "action": action,
                "mismatched": list(fields),
                "approved_plan_hash": intent.plan_hash[:12],
                "current_plan_hash": plan_hash[:12],
                "approved_engine": intent.engine,
                "current_engine": engine,
                "approved_target": intent.target_identity,
                "current_target": target_identity,
            },
        )
    return intent


def require_explicit_approval(
    action: str,
    *,
    approved: bool,
    allow_implicit: bool | None = None,
) -> None:
    """Gate a mutating act behind an explicit approval flag.

    The simpler sibling of :func:`require_execution_intent` for surfaces with
    no compiled plan to bind to (recovery sweeps, dependency installs):
    ``approved`` is the command's own explicit opt-in. Like its sibling it is
    pure — the environment switch is read by the application layer and passed
    in as ``allow_implicit``.

    Raises:
        ExecutionIntentRefused: With code :data:`INTENT_REQUIRED`.
    """
    if approved:
        return
    if implicit_execution_requested(allow_implicit):
        return
    raise ExecutionIntentRefused(
        INTENT_REQUIRED,
        f"{action} refused: {action} mutates the target and needs an explicit "
        "approval flag",
        details={"action": action, "implicit_execution_env": IMPLICIT_EXECUTION_ENV},
    )


def intent_for_plan(
    plan: object,
    *,
    engine: str = "",
    target_identity: str = "",
    policy_id: str = "",
    blast_radius: Mapping[str, Any] | None = None,
    actor: str = "cli",
    ttl_s: float | None = DEFAULT_APPROVAL_TTL_S,
    approved_at: float | None = None,
    break_glass: bool = False,
) -> ExecutionIntent:
    """Mint an :class:`ExecutionIntent` bound to ``plan``.

    The plan hash is computed with the same
    :func:`mayhem.domain.preflight.plan_hash_for` the preflight uses, so the
    intent and the gate always agree on what "this plan" means.
    """
    from mayhem.domain.preflight import plan_hash_for

    moment = time.time() if approved_at is None else approved_at
    expires = None if ttl_s is None else moment + float(ttl_s)
    return ExecutionIntent(
        plan_hash=plan_hash_for(plan),
        engine=engine,
        target_identity=target_identity,
        policy_id=policy_id,
        blast_radius=dict(blast_radius or {}),
        actor=actor,
        approved_at=moment,
        expires_at=expires,
        break_glass=break_glass,
    )
