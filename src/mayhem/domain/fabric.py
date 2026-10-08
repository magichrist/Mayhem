"""Distributed execution fabric — protocol vocabulary and step semantics.

Plan ``docs/v1.1.0/03_EXECUTION_FABRIC.md``, Phase 1: the *words* of the fabric
before any of its machinery. One execution protocol has to serve local engines,
Kubernetes agents, hosts, clouds, and third-party fault providers, so the
vocabulary is stated once here and referenced everywhere else:

* :class:`FabricCommand` — the signed-command envelope. A command names the
  frozen plan it belongs to (``plan_digest``), carries a single-use ``nonce``,
  repeats nothing under an ``idempotency_key``, proves ownership with a
  :class:`FencingToken`, and points at its body through a :class:`CommandBodyRef`
  instead of inlining the payload.
* :class:`FencingToken` — the monotonic ordering predicate. Exactly one owner per
  step survives controller failover because every command must be stamped with a
  token at least as new as the highest one the agent has already served.
* :class:`StepSemantics` — the orchestration constructs (gap 16) as *planner*
  types, not provider behaviour: what a step means, which fields make that
  meaning well-formed, and nothing about how a provider runs it.
* :class:`Reservation` — the resource lock that feeds 07's ``ResourceLock``
  (gap 86): resource id, owning run and step, holder, fencing token, expiry.

Three properties are the point of the phase, and each is a *type* property, not
a runtime check somebody can forget to call:

1. **An unsigned command is unrepresentable.** ``signature`` and
   ``signing_key_id`` are required fields with no defaults, and no field has a
   default at all — there is no construction path that omits them.
2. **A replayed command is refused by a predicate.** ``FabricCommand.is_replayed``
   and the pure :class:`NonceLedger` decide it from the nonce alone; the ledger
   refuses to record the same nonce twice.
3. **An unbounded loop is unrepresentable.** A ``loop`` step is well-formed only
   with both an iteration ``bound`` and a ``budget_ref``, enforced by
   :func:`require_well_formed` on the enum's own table.

Everything here is a value: no IO, no clock read (callers pass ``now``), no
crypto (the envelope states *what* was signed — :meth:`FabricCommand.signing_payload`
— verification arrives with plan 19's identities). The domain layer stays free of
``mayhem.toolkit``/``agents``/``controller``/``infra`` and of ``asyncio``,
``socket``, ``subprocess``, ``sqlite3``, ``pathlib``, ``os`` per the
"Domain layer has zero IO and no upward imports" contract.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from datetime import datetime, timedelta
from enum import StrEnum
from types import MappingProxyType
from typing import Annotated, Final

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

from mayhem.domain.common import Duration, parse_duration, utc_now
from mayhem.domain.errors import DomainError, InvariantViolationError, SchemaValidationError
from mayhem.domain.hashing import canonical_json

#: Wire protocol this vocabulary speaks. The ``mayhem/1`` framing of
#: :mod:`mayhem.agents.protocol` (ndjson JSON-RPC, ``run_id``/``agent_id``
#: correlation) stays the transport; this is the successor rule set that plan 03
#: Phase 6 documents, and a command that claims any other version is refused at
#: construction rather than on the wire.
FABRIC_PROTOCOL_VERSION: Final[str] = "mayhem/1"

#: Stable refusal codes. Part of the fabric's error contract. Every one of them
#: is raised by a *decision* function below, except :data:`FABRIC_UNDERSIGNED`,
#: which a receiver raises when a frame off the wire fails the envelope's own
#: signature constraints — the envelope makes it unrepresentable, so the wire
#: path is the only place that can see it.
FABRIC_UNDERSIGNED = "fabric_undersigned"
FABRIC_REPLAYED_NONCE = "fabric_replayed_nonce"
FABRIC_STALE_FENCE = "fabric_stale_fence"
FABRIC_PLAN_MISMATCH = "fabric_plan_mismatch"
FABRIC_RESOURCE_CONFLICT = "fabric_resource_conflict"
FABRIC_RESERVATION_EXPIRED = "fabric_reservation_expired"

_REMEDIATION = (
    "a fabric command must be minted by the controller with plan_digest, nonce, "
    "idempotency_key, fencing_token, and a signature over signing_payload()"
)

# --- scalar vocabulary --------------------------------------------------------
# Identifiers stay loose enough for the ids the rest of the system already mints
# (``r-intent-1``, ``l-…``, ``pod/web-0``) and tight enough that an empty string
# is a validation error rather than a silent "no owner".
_Ident = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}$")]

#: A plan digest is the same 64-hex sha256 :func:`mayhem.domain.preflight.plan_hash_for`
#: produces, so the intent gate, the evidence seal, and the fabric agree on what
#: "this plan" means.
PlanDigest = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]

_BodyDigest = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]

#: A nonce is single-use and per-command: it is never derived from the command
#: body, so a replayed body cannot launder a fresh nonce.
_Nonce = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{32,128}$")]

#: A signature is opaque to the domain (verification is plan 19's job) but it is
#: not allowed to be empty, blank, or punctuation.
_Signature = Annotated[
    str, StringConstraints(min_length=16, max_length=1024, pattern=r"^[A-Za-z0-9+/=_-]+$")
]

_KeyId = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9._@:/-]{0,127}$")]


class FabricCommandRefused(DomainError):  # noqa: N818 — public API, not a stdlib error
    """A fabric command was refused before it could act.

    Attributes:
        code: One of :data:`FABRIC_UNDERSIGNED`, :data:`FABRIC_REPLAYED_NONCE`,
            :data:`FABRIC_STALE_FENCE`, :data:`FABRIC_PLAN_MISMATCH`,
            :data:`FABRIC_RESOURCE_CONFLICT`, or
            :data:`FABRIC_RESERVATION_EXPIRED`.
        details: Stable, secret-free context (short ids and codes, never bodies).
        remediation: Human-readable next step.
    """

    def __init__(
        self,
        code: str,
        message: str,
        *,
        details: Mapping[str, object] | None = None,
        remediation: str = _REMEDIATION,
    ) -> None:
        self.code = code
        self.details: dict[str, object] = dict(details or {})
        self.remediation = remediation
        super().__init__(message)


def _require_aware(moment: datetime, rule: str, subject: str) -> None:
    """Refuse naive datetimes (DTZ discipline, and a naive fence is unusable)."""
    if moment.tzinfo is None:
        raise InvariantViolationError(
            rule, f"{subject} must be timezone-aware, got naive {moment!r}"
        )


# --- fencing ------------------------------------------------------------------


class FencingToken(BaseModel):
    """Ownership of one step, ordered monotonically.

    A controller failover mints a *newer* token for the same ``(run_id, step_id)``.
    An agent that has already served token 7 refuses anything below 7, so two
    owners can never both believe they hold the step. Epochs start at 1 — a
    zero-epoch token is "no ownership", which is exactly what an unsigned or
    deposed command would need and must not be able to say.

    Attributes:
        run_id: Run the step belongs to.
        step_id: Step being owned.
        holder: Agent the ownership was issued to.
        epoch: Monotonic counter, 1-based.
        issued_at: When the fence was minted (tz-aware).
        supersedes_epoch: Epoch this token replaced, when it is a handover.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    run_id: _Ident
    step_id: _Ident
    holder: _Ident
    epoch: Annotated[int, Field(ge=1)]
    issued_at: datetime
    supersedes_epoch: Annotated[int, Field(ge=1)] | None = None

    @model_validator(mode="after")
    def _ordering(self) -> FencingToken:
        _require_aware(self.issued_at, "fence_time_ordering", f"fence for step '{self.step_id}'")
        if self.supersedes_epoch is not None and self.supersedes_epoch >= self.epoch:
            raise InvariantViolationError(
                "fence_supersede_ordering",
                f"fence for step '{self.step_id}' claims epoch {self.epoch} while superseding "
                f"{self.supersedes_epoch}; a handover must strictly increase",
            )
        return self

    @classmethod
    def issue(
        cls,
        *,
        run_id: str,
        step_id: str,
        holder: str,
        now: datetime | None = None,
    ) -> FencingToken:
        """Mint the first fence (epoch 1) for a step."""
        return cls(
            run_id=run_id,
            step_id=step_id,
            holder=holder,
            epoch=1,
            issued_at=utc_now() if now is None else now,
        )

    def next_fence(self, *, holder: str, now: datetime | None = None) -> FencingToken:
        """Return the immediate successor of this fence.

        The only supported way to grow an epoch, so a controller failover cannot
        mint a fence that is not strictly newer than the one it replaced.
        """
        return self.__class__(
            run_id=self.run_id,
            step_id=self.step_id,
            holder=holder,
            epoch=self.epoch + 1,
            issued_at=utc_now() if now is None else now,
            supersedes_epoch=self.epoch,
        )

    def same_scope(self, other: FencingToken) -> bool:
        """True when both fences claim the same step of the same run."""
        return self.run_id == other.run_id and self.step_id == other.step_id

    def is_after(self, other: FencingToken) -> bool:
        """True when this fence is strictly newer than ``other`` for the same step."""
        return self.same_scope(other) and self.epoch > other.epoch

    def is_at_least(self, other: FencingToken) -> bool:
        """True when this fence is as new as (or newer than) ``other``.

        This is the dispatch predicate: a command is served only when its own
        fence is not older than the highest fence the receiver has already seen.
        """
        return self.same_scope(other) and self.epoch >= other.epoch

    def outranks(self, other: FencingToken) -> bool:
        """Inverse of :meth:`is_at_least`, for readability at call sites."""
        return other.is_at_least(self)


# --- command body reference ---------------------------------------------------


class FabricCommandType(StrEnum):
    """The fabric's protocol verbs (plan 03 §Protocol).

    ``prepare -> reserve -> validate -> inject -> observe -> compensate ->
    verify -> close``
    """

    PREPARE = "prepare"
    RESERVE = "reserve"
    VALIDATE = "validate"
    INJECT = "inject"
    OBSERVE = "observe"
    COMPENSATE = "compensate"
    VERIFY = "verify"
    CLOSE = "close"


class CommandBodyRef(BaseModel):
    """A reference to a command body, never the body itself.

    The envelope stays small and comparable: two commands with the same
    ``body_digest`` are the same effect regardless of how the body is
    transported, which is what makes idempotent retries decidable in Phase 2.

    Attributes:
        command_type: Which protocol verb this body performs.
        body_digest: sha256 of the canonical body.
        body_ref: Opaque locator the agent resolves (transport-owned).
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    command_type: FabricCommandType
    body_digest: _BodyDigest
    body_ref: _Ident


class FabricCommand(BaseModel):
    """The signed-command envelope every fabric dispatch travels in.

    Not one field here has a default. That is the enforcement mechanism: an
    unsigned command is not "rejected later", it has no constructor, and
    ``extra="forbid"`` means the missing pieces cannot be smuggled in as extras
    either. ``plan_digest`` binds the command to the frozen plan (a command
    against a superseded plan is refused — Phase 4), ``nonce`` makes a replay
    detectable, ``idempotency_key`` makes a retry safe, ``fencing_token`` makes
    double ownership impossible, and ``command`` points at the body.

    Attributes:
        protocol: Must equal :data:`FABRIC_PROTOCOL_VERSION`.
        command_id: Stable id of this dispatch (``fc-…``).
        run_id: Correlation id, mirroring the frame-level ``run_id`` of
            ``agents/protocol.py``.
        step_id: Step this command acts on.
        agent_id: The agent the command is addressed to (``agents/protocol.py``
            correlation, restated here so an envelope is self-describing).
        plan_digest: Digest of the frozen plan this command was minted from.
        nonce: Single-use value; never reused for a different command.
        idempotency_key: Stable across retries of the *same* effect.
        fencing_token: Ownership stamp for the step.
        command: The body reference.
        issued_at: When the controller minted the command (tz-aware).
        signing_key_id: Which key produced ``signature`` (identities arrive with 19).
        signature: Signature over :meth:`signing_payload`.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    protocol: str
    command_id: _Ident
    run_id: _Ident
    step_id: _Ident
    agent_id: _Ident
    plan_digest: PlanDigest
    nonce: _Nonce
    idempotency_key: _Ident
    fencing_token: FencingToken
    command: CommandBodyRef
    issued_at: datetime
    signing_key_id: _KeyId
    signature: _Signature

    @model_validator(mode="after")
    def _envelope(self) -> FabricCommand:
        if self.protocol != FABRIC_PROTOCOL_VERSION:
            raise InvariantViolationError(
                "fabric_protocol_version",
                f"command '{self.command_id}' speaks {self.protocol!r}; "
                f"this fabric speaks {FABRIC_PROTOCOL_VERSION!r}",
            )
        _require_aware(self.issued_at, "fabric_command_time", f"command '{self.command_id}'")
        return self

    @property
    def is_signed(self) -> bool:
        """Always true for a constructed command; stated so callers can assert it.

        The field constraints on ``signature``/``signing_key_id`` are what make
        this true — an unsigned envelope fails validation, so it never reaches
        this property. A receiver decoding a frame off the wire turns that
        validation failure into a refusal carrying :data:`FABRIC_UNDERSIGNED`.
        """
        return bool(self.signature.strip()) and bool(self.signing_key_id.strip())

    def signing_payload(self) -> str:
        """Canonical bytes the signature must cover (the envelope minus signature).

        Deterministic by construction: :func:`mayhem.domain.hashing.canonical_json`
        over the JSON-mode dump with the signature field removed, so signer and
        verifier cannot disagree about what was signed.
        """
        return canonical_json(self.model_dump(mode="json", exclude={"signature"}))

    def binds_to(self, plan_digest: str) -> bool:
        """True when this command was minted against ``plan_digest``."""
        return self.plan_digest == plan_digest

    def is_replayed(self, consumed_nonces: Iterable[str]) -> bool:
        """True when this command's nonce was already consumed.

        The predicate is total: a nonce is single-use, so the answer does not
        depend on timing, on the body, or on who is asking. ``False`` means the
        caller must record the nonce (see :meth:`NonceLedger.accept`) before
        acting, never after.
        """
        return self.nonce in frozenset(consumed_nonces)

    def guards(self, served_fence: FencingToken) -> bool:
        """True when this command's fence is not older than the served one.

        ``False`` means the command comes from a deposed owner and must be
        refused with :data:`FABRIC_STALE_FENCE`.
        """
        return self.fencing_token.is_at_least(served_fence)

    def is_stale_against(self, served_fence: FencingToken) -> bool:
        """Inverse of :meth:`guards`."""
        return not self.guards(served_fence)

    def same_effect_as(self, other: FabricCommand) -> bool:
        """True when a retry may be collapsed onto this command.

        Same idempotency key *and* same body digest: the same key with a
        different body is a key collision, not a retry.
        """
        return (
            self.idempotency_key == other.idempotency_key
            and self.command.body_digest == other.command.body_digest
        )


class NonceLedger(BaseModel):
    """Append-only record of consumed nonces.

    Pure and immutable: :meth:`accept` returns a *new* ledger, so two agents
    that consumed the same nonce cannot share a state and therefore cannot both
    decide the command is fresh.

    Attributes:
        consumed: Nonces already spent.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    consumed: frozenset[str] = frozenset()

    def knows(self, nonce: str) -> bool:
        return nonce in self.consumed

    def accept(self, command: FabricCommand) -> NonceLedger:
        """Record ``command``'s nonce and return the advanced ledger.

        Raises:
            FabricCommandRefused: With code :data:`FABRIC_REPLAYED_NONCE` when
                the nonce was already spent. The refusal is the property the
                ledger exists to guarantee.
        """
        if command.is_replayed(self.consumed):
            raise FabricCommandRefused(
                FABRIC_REPLAYED_NONCE,
                f"command '{command.command_id}' replays nonce {command.nonce[:8]}…",
                details={"command_id": command.command_id, "run_id": command.run_id},
                remediation="mint a fresh nonce for every dispatch; a retry reuses the "
                "idempotency key, never the nonce",
            )
        return self.__class__(consumed=self.consumed | {command.nonce})


# --- step semantics -----------------------------------------------------------


class StepSemantics(StrEnum):
    """What a planner-level step *means* (gap 16).

    These are constructs of the execution plan, not provider behaviour: a
    ``branch`` decides which step runs next, a ``join`` names the branches it
    waits on, a ``loop`` iterates under a bound *and* a budget, a ``compensate``
    always names the step it undoes and the probe that proves the undo. A Docker
    executor and a Chaos Mesh executor execute the same semantics; neither
    reinterprets them.
    """

    SERIAL = "serial"
    PARALLEL = "parallel"
    CONDITIONAL = "conditional"
    LOOP = "loop"
    RETRY = "retry"
    TIMEOUT = "timeout"
    BRANCH = "branch"
    JOIN = "join"
    WAIT = "wait"
    APPROVAL = "approval"
    COMPENSATE = "compensate"


#: Fields each semantic must state to be well-formed. ``SERIAL`` states none:
#: ordering in a serial step is the plan's own sequence, and demanding a
#: predecessor for the first step would be wrong.
SEMANTIC_REQUIRED_FIELDS: Final[Mapping[StepSemantics, frozenset[str]]] = MappingProxyType(
    {
        StepSemantics.SERIAL: frozenset(),
        StepSemantics.PARALLEL: frozenset({"fan_out_step_ids"}),
        StepSemantics.CONDITIONAL: frozenset({"condition_ref"}),
        StepSemantics.LOOP: frozenset({"bound", "budget_ref"}),
        StepSemantics.RETRY: frozenset({"retry_limit", "backoff_ref"}),
        StepSemantics.TIMEOUT: frozenset({"timeout_s"}),
        StepSemantics.BRANCH: frozenset({"condition_ref", "branch_targets"}),
        StepSemantics.JOIN: frozenset({"join_step_ids"}),
        StepSemantics.WAIT: frozenset({"wait_ref", "timeout_s"}),
        StepSemantics.APPROVAL: frozenset({"approval_ref"}),
        StepSemantics.COMPENSATE: frozenset({"compensates_step_id", "verify_probe_ref"}),
    }
)

#: Counters that must be a positive integer (a bound of zero is no loop; a
#: negative one is nonsense).
_POSITIVE_INT_FIELDS: Final[frozenset[str]] = frozenset({"bound", "retry_limit"})

#: Quantities that must be a positive number.
_POSITIVE_NUMBER_FIELDS: Final[frozenset[str]] = frozenset({"timeout_s"})

#: References (``budget_ref``, ``condition_ref``, ``approval_ref``, …) and
#: collections (``branch_targets``, ``join_step_ids``, …) need no value check of
#: their own: a blank string and an empty tuple are both caught as unstated by
#: :func:`_is_stated`. Only the two numeric carriers below need one.


def _is_stated(value: object) -> bool:
    """True when a carrier field actually says something.

    ``None`` and the empty string/tuple/list/dict all count as unstated: a
    planner that emits ``condition_ref=""`` has not named a condition.
    """
    if value is None:
        return False
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, (tuple, list, set, frozenset, dict)):
        return len(value) > 0
    return True


def _as_positive_number(value: object) -> float | None:
    """Read a quantity as a float, or ``None`` when it is not one.

    A ``Duration`` field reads back as a seconds *string* when a model is
    dumped, so the same grammar the DSL documents ("30s" / "5m" / "1h") is
    reused here rather than a second, weaker copy of it.
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(parse_duration(value))
        except SchemaValidationError:
            return None
    return None


def step_semantics_violations(
    semantic: StepSemantics,
    fields: Mapping[str, object],
) -> tuple[str, ...]:
    """Name every way ``fields`` fails to make ``semantic`` well-formed.

    Returns an empty tuple when the step is well-formed. The checks are
    presence first, then value sanity, so the violation text says which of the
    two went wrong: ``"loop.bound is required"`` versus
    ``"loop.bound must be a positive integer, got 0"``.
    """
    violations: list[str] = []
    for name in sorted(SEMANTIC_REQUIRED_FIELDS[semantic]):
        value = fields.get(name)
        if not _is_stated(value):
            violations.append(f"{semantic.value}.{name} is required")
            continue
        if name in _POSITIVE_INT_FIELDS and (
            isinstance(value, bool) or not isinstance(value, int) or value < 1
        ):
            violations.append(f"{semantic.value}.{name} must be a positive integer, got {value!r}")
        if name in _POSITIVE_NUMBER_FIELDS:
            number = _as_positive_number(value)
            if number is None or number <= 0.0:
                violations.append(
                    f"{semantic.value}.{name} must be a positive number, got {value!r}"
                )
    return tuple(violations)


def is_well_formed(semantic: StepSemantics, fields: Mapping[str, object]) -> bool:
    """Predicate form of :func:`step_semantics_violations`."""
    return not step_semantics_violations(semantic, fields)


def require_well_formed(semantic: StepSemantics, fields: Mapping[str, object]) -> None:
    """Assert that ``fields`` make ``semantic`` well-formed.

    Raises:
        InvariantViolationError: With rule ``step_semantics_ill_formed`` and one
            line per violation.
    """
    violations = step_semantics_violations(semantic, fields)
    if violations:
        raise InvariantViolationError(
            "step_semantics_ill_formed",
            f"{semantic.value} step is ill-formed: " + "; ".join(violations),
        )


class StepSpec(BaseModel):
    """A planner-level step, typed by the semantics it carries.

    The carriers are all optional *fields* because one flat model has to be able
    to express eleven semantics; the well-formedness rule is not optional —
    :meth:`_well_formed` runs :func:`require_well_formed` on every construction,
    so an unbounded ``loop`` or a conditionless ``branch`` is not constructible.

    Attributes:
        step_id: Step identity within the plan.
        semantic: What the step means.
        depends_on: Steps that must complete first.
        fan_out_step_ids: Siblings started together (``parallel``).
        condition_ref: Reference to the predicate deciding the step (``conditional``/``branch``).
        branch_targets: Steps each branch outcome may enter (``branch``).
        bound: Maximum iterations; required, and at least 1, for a ``loop``.
        budget_ref: Budget the loop charges against (plan 13's budget hierarchy).
        retry_limit: Maximum attempts; required, and at least 1, for a ``retry``.
        backoff_ref: Backoff policy reference.
        timeout_s: Deadline; required, and positive, for ``timeout``/``wait``.
        join_step_ids: Steps a ``join`` waits for.
        wait_ref: What a ``wait`` waits on.
        approval_ref: The approval record an ``approval`` step gates on.
        compensates_step_id: The step a ``compensate`` step undoes.
        verify_probe_ref: The probe that proves the undo happened.
        issued_at: When the planner emitted the step (tz-aware).
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    step_id: _Ident
    semantic: StepSemantics
    depends_on: tuple[_Ident, ...] = ()
    fan_out_step_ids: tuple[_Ident, ...] = ()
    condition_ref: str | None = None
    branch_targets: tuple[_Ident, ...] = ()
    bound: int | None = None
    budget_ref: str | None = None
    retry_limit: int | None = None
    backoff_ref: str | None = None
    timeout_s: Duration | None = None
    join_step_ids: tuple[_Ident, ...] = ()
    wait_ref: str | None = None
    approval_ref: str | None = None
    compensates_step_id: str | None = None
    verify_probe_ref: str | None = None
    issued_at: datetime = Field(default_factory=utc_now)

    @model_validator(mode="after")
    def _well_formed(self) -> StepSpec:
        _require_aware(self.issued_at, "step_time_ordering", f"step '{self.step_id}'")
        require_well_formed(self.semantic, self.model_dump())
        return self

    @property
    def is_compensating(self) -> bool:
        return self.semantic is StepSemantics.COMPENSATE

    def iteration_cap(self) -> int | None:
        """The cap on how often this step may run its body.

        The cap for ``loop`` (``bound``) or ``retry`` (``retry_limit``), and
        ``None`` for a step that runs once. ``None`` is never returned for a
        ``loop``: :meth:`_well_formed` refuses to construct one without a bound.
        """
        if self.semantic is StepSemantics.LOOP:
            return self.bound
        if self.semantic is StepSemantics.RETRY:
            return self.retry_limit
        return None


# --- reservations -------------------------------------------------------------


class Reservation(BaseModel):
    """An experiment-scoped resource lock (feeds 07's ``ResourceLock``, gap 86).

    Two steps must not fight over the same resource, and after a controller
    failover the deposed owner must not keep it. Both are answered here: a
    reservation names its owning run and step, and the :class:`FencingToken` it
    was taken under, so a lock held under a stale fence is recognisable as
    stale rather than as contention.

    Attributes:
        resource_id: What is locked (``svc/checkout``, ``node/worker-3``, …).
        run_id: Owning run.
        step_id: Owning step.
        holder: Agent holding the lock.
        fencing_token: The fence this reservation was taken under.
        ttl_seconds: Lease-style TTL; a reservation is never held forever.
        acquired_at: When the lock was taken (tz-aware).
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    resource_id: _Ident
    run_id: _Ident
    step_id: _Ident
    holder: _Ident
    fencing_token: FencingToken
    ttl_seconds: Duration = 120.0
    acquired_at: datetime = Field(default_factory=utc_now)

    @model_validator(mode="after")
    def _lock(self) -> Reservation:
        _require_aware(
            self.acquired_at, "reservation_time_ordering", f"reservation on '{self.resource_id}'"
        )
        if float(self.ttl_seconds) <= 0.0:
            raise InvariantViolationError(
                "reservation_positive_ttl",
                f"reservation on '{self.resource_id}' needs a positive TTL, "
                f"got {self.ttl_seconds!r}",
            )
        if (self.fencing_token.run_id, self.fencing_token.step_id) != self.owner:
            raise InvariantViolationError(
                "reservation_fence_scope",
                f"reservation on '{self.resource_id}' is held under a fence for "
                f"{self.fencing_token.run_id}/{self.fencing_token.step_id}, not {self.owner[0]}/"
                f"{self.owner[1]}",
            )
        return self

    @property
    def owner(self) -> tuple[str, str]:
        """``(run_id, step_id)`` — the pair that must be unique per resource."""
        return (self.run_id, self.step_id)

    @property
    def expires_at(self) -> datetime:
        return self.acquired_at + timedelta(seconds=float(self.ttl_seconds))

    def is_expired(self, now: datetime | None = None) -> bool:
        """True once the TTL has passed. Never an unbounded lock."""
        moment = utc_now() if now is None else now
        return moment >= self.expires_at

    def remaining_s(self, now: datetime | None = None) -> float:
        """Seconds of TTL left, floored at zero."""
        moment = utc_now() if now is None else now
        return max(0.0, (self.expires_at - moment).total_seconds())

    def is_authorised_by(self, presented: FencingToken) -> bool:
        """True when ``presented`` is a fence this reservation legitimately holds.

        A presented fence older than the one the lock was taken under comes
        from a deposed owner and may not act on the resource.
        """
        return self.fencing_token.is_at_least(presented)

    def conflicts_with(self, other: Reservation, *, now: datetime | None = None) -> bool:
        """True when both hold the same resource for different owners.

        An expired reservation conflicts with nothing: a lock nobody may use
        again is not contention. ``now`` is injected so the check is
        reproducible in tests and in a dry run.
        """
        if self.resource_id != other.resource_id:
            return False
        if self.owner == other.owner:
            return False
        return not (self.is_expired(now) or other.is_expired(now))

    def renew(self, *, ttl_seconds: Duration, now: datetime | None = None) -> Reservation:
        """Return a new reservation with a fresh TTL.

        Raises:
            FabricCommandRefused: With code :data:`FABRIC_RESERVATION_EXPIRED`
                when the lock had already lapsed — renewing an expired lock would
                resurrect ownership nobody holds.
        """
        moment = utc_now() if now is None else now
        if self.is_expired(moment):
            raise FabricCommandRefused(
                FABRIC_RESERVATION_EXPIRED,
                f"reservation on '{self.resource_id}' expired at {self.expires_at.isoformat()}",
                details={"resource_id": self.resource_id, "run_id": self.run_id},
                remediation="re-reserve under a current fencing token instead of renewing",
            )
        return self.__class__(
            resource_id=self.resource_id,
            run_id=self.run_id,
            step_id=self.step_id,
            holder=self.holder,
            fencing_token=self.fencing_token,
            ttl_seconds=ttl_seconds,
            acquired_at=moment,
        )


def reservation_conflicts(
    reservations: Iterable[Reservation],
    *,
    now: datetime | None = None,
) -> tuple[Reservation, ...]:
    """Every reservation that collides with an earlier one in ``reservations``.

    Pure lock-table check over an unordered grab: the returned reservation is
    the *later* claim on a resource another owner already holds. Pairwise, so a
    caller can decide whether to refuse, wait, or escalate with
    :data:`FABRIC_RESOURCE_CONFLICT`.
    """
    claimed = _ReservationTable()
    clashes: list[Reservation] = []
    for reservation in reservations:
        if not claimed.claimable(reservation, now=now):
            clashes.append(reservation)
        claimed = claimed.with_(reservation)
    return tuple(clashes)


class _ReservationTable(BaseModel):
    """Internal: resource -> the live reservation holding it."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    held: Mapping[str, Reservation] = Field(default_factory=dict)

    def claimable(self, reservation: Reservation, *, now: datetime | None = None) -> bool:
        current = self.held.get(reservation.resource_id)
        if current is None or current.is_expired(now):
            return True
        return current.owner == reservation.owner

    def with_(self, reservation: Reservation) -> _ReservationTable:
        return self.__class__(held={**self.held, reservation.resource_id: reservation})


def assert_plan_digest_matches(
    command: FabricCommand,
    *,
    current_plan_digest: str,
) -> None:
    """Refuse a command minted against a superseded plan (plan 03 Phase 4).

    Raises:
        FabricCommandRefused: With code :data:`FABRIC_PLAN_MISMATCH`.
    """
    if not command.binds_to(current_plan_digest):
        raise FabricCommandRefused(
            FABRIC_PLAN_MISMATCH,
            f"command '{command.command_id}' is bound to plan {command.plan_digest[:12]}… "
            f"but the frozen plan is now {current_plan_digest[:12]}…",
            details={"command_id": command.command_id, "step_id": command.step_id},
            remediation="approvals are invalidated by a plan change; re-plan and re-approve",
        )


def assert_fence_current(command: FabricCommand, *, served_fence: FencingToken) -> None:
    """Refuse a command from a deposed owner.

    Raises:
        FabricCommandRefused: With code :data:`FABRIC_STALE_FENCE`.
    """
    if command.is_stale_against(served_fence):
        raise FabricCommandRefused(
            FABRIC_STALE_FENCE,
            f"command '{command.command_id}' carries fence {command.fencing_token.epoch} but "
            f"step '{command.step_id}' is already served under fence {served_fence.epoch}",
            details={"command_id": command.command_id, "step_id": command.step_id},
            remediation="the newer fence owns the step; the older command must be dropped",
        )


def assert_reservation_available(
    reservation: Reservation,
    *,
    held: Sequence[Reservation] = (),
    now: datetime | None = None,
) -> None:
    """Refuse a reservation that collides with a live lock.

    Raises:
        FabricCommandRefused: With code :data:`FABRIC_RESOURCE_CONFLICT`.
    """
    clashes = [other for other in held if other.conflicts_with(reservation, now=now)]
    if clashes:
        names = ", ".join(
            f"{other.resource_id} held by {other.owner[0]}/{other.owner[1]}" for other in clashes
        )
        raise FabricCommandRefused(
            FABRIC_RESOURCE_CONFLICT,
            f"reservation on '{reservation.resource_id}' collides with {names}",
            details={"resource_id": reservation.resource_id, "run_id": reservation.run_id},
            remediation="wait for the held reservation to expire, or re-plan with a wider scope",
        )
