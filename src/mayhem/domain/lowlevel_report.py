"""The explanation surface for plan 04's low-level primitives — Phase 3.

Why a separate module, and what it is not
-----------------------------------------
Phase 1 declared 22 primitive descriptors in :mod:`mayhem.domain.lowlevel` and
Phase 2 turned 18 blocked ones into four ``catalog_only`` refusals plus fourteen
written decisions. None of that is reachable by a person. ``mayhem discover
faults -e`` explains a *fault id*, and for fourteen primitives there is no fault
id — including all six ``jvm.*`` descriptors, which have no catalog surface at
all. A user asking "how do I delay a Java method?" is told about
``app.exception`` and nothing else.

This module is that missing surface. :func:`explain_primitive` answers, for one
primitive: what it would attach, what that costs in capabilities, how it comes
back, what to look at afterwards, what parameters it takes, and — the part that
matters — **why it is not going to happen**.

What it is not
--------------
It is not a mechanism, and it does not pretend to be one. Nothing here loads an
eBPF program, opens a FUSE mount, creates a device-mapper target, or attaches a
JVM agent; nothing here can, on any host, with or without privileges. That is why
the answer carries a field called :attr:`PrimitiveExplanation.mechanism_applied`
which is ``False`` by construction **and refused if set to** ``True``: promoting
it requires a real mechanism, and the model's validator is where "there is
nothing to render as applied" is enforced rather than described.

This is the same split :mod:`mayhem.providers.sandbox` makes, and the same
sentence-structure:

* the **decision** — which primitive to attempt, whether the attempt is
  admissible, at what magnitude, with what undo — is pure, testable, and total;
* the **mechanism** — the privileged operation — is behind a port that is
  unbound in this build, and its unboundness is a *named* unavailability rather
  than an absence of code.

:data:`LOWLEVEL_NOT_ATTACHED_NOTICE` is that naming, in one sentence a surface
cannot print without.

Decision tables, moved here so there is exactly one of each
-------------------------------------------------------------
Phase 2 recorded its selection rule — which blocked primitive got a catalog id
and which did not, and why — as literals inside its own test file. That is a real
limitation of a *test* as a home for a decision: a reader of the product has
nowhere to read which rule sent a primitive to descriptor-only, and a CLI cannot
print it. Both tables live here now, and ``tests/unit/test_lowlevel_refusals.py``
inverts them rather than restating them, so the Phase-2 contract is checked
against one source.

The exhaustiveness of the pair is the property worth keeping: every primitive
whose :meth:`~mayhem.domain.lowlevel.LowLevelPrimitive.substrate_verdict` is
false appears in exactly one of :data:`CATALOG_REFUSAL_BY_PRIMITIVE` or
:data:`DESCRIPTOR_ONLY_RULES`, and :func:`disposition_problems` returns the
disagreement as data — the same shape :func:`mayhem.domain.lowlevel.
registry_problems` uses, and deliberately not run at import.
"""

from __future__ import annotations

from enum import StrEnum
from types import MappingProxyType
from typing import TYPE_CHECKING, Final

from pydantic import BaseModel, ConfigDict, Field, model_validator

from mayhem.domain.catalog import definition_for
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.lowlevel import (
    CURRENT_SUBSTRATE,
    PRIMITIVES,
    LowLevelPrimitive,
    descriptor_for,
    magnitude_holder,
    parameter_grammar,
)

if TYPE_CHECKING:
    from collections.abc import Mapping

    from mayhem.domain.lowlevel import CapabilityGap, SubstrateSurface

__all__ = [
    "CATALOG_REFUSAL_BY_PRIMITIVE",
    "DESCRIPTOR_ONLY_RULES",
    "LOWLEVEL_NOT_ATTACHED_NOTICE",
    "MISSING_MECHANISM_NONE",
    "RULE_IDS",
    "ConsistencyProblem",
    "PrimitiveAvailability",
    "PrimitiveDisposition",
    "PrimitiveExplanation",
    "blocked_primitives",
    "describe_explanation",
    "describe_primitive",
    "disposition_problems",
    "explain_primitive",
    "explain_primitives",
]


#: What a primitive with no missing mechanism prints in the mechanism slot. It has
#: one, by definition: the active catalog fault that already carries it. A blank
#: would read as "mayhem does not know", which is a different and wrong finding.
MISSING_MECHANISM_NONE: Final[str] = "the active catalog fault's own mechanism"

#: The sentence every explanation carries.
#:
#: Deliberately a module constant rather than a docstring, for the reason
#: :data:`mayhem.providers.sandbox.SANDBOX_NOT_ENFORCED_NOTICE` is one: a surface
#: that renders an explanation must be able to render the caveat next to it
#: without having to remember the wording. It names the four mechanism classes
#: this plan is about and says plainly that none of them ran.
LOWLEVEL_NOT_ATTACHED_NOTICE: Final[str] = (
    "mayhem decides which low-level primitive to attempt and refuses every one it cannot "
    "perform. In this build it attaches no eBPF program, creates no FUSE mount or "
    "device-mapper target, and loads no JVM agent, so no primitive described here has been "
    "injected on any host. Read a primitive as a contract a mechanism must satisfy, never as "
    "evidence that a fault was injected."
)


# ── the Phase-2 selection rule, as data a product can read ───────────────────

#: Blocked primitives that a ``catalog_only`` entry already answers for.
#:
#: One row per *primitive*, keyed by primitive id rather than by fault id, because
#: the reader of this table is a person asking about a primitive. Phase 2 grouped
#: them the other way round (``fault id -> the primitives it covers``), which is
#: the right shape for asserting "one refusal per mechanism" and the wrong shape
#: for answering "what happens to *this* primitive". Both are derived from this
#: table by the Phase-2 suite.
CATALOG_REFUSAL_BY_PRIMITIVE: Final[Mapping[str, str]] = MappingProxyType(
    {
        "kernel.syscall_errno": "process.syscall_error",
        "kernel.syscall_latency": "process.syscall_error",
        "kernel.syscall_return_mutation": "process.syscall_return_mutation",
        "io.read_delay": "fs.read_delay",
        "io.write_delay": "fs.read_delay",
        "io.block_device_delay": "fs.block_device_delay",
    }
)

#: Blocked primitives that get **no** catalog id, and the rule that decided it.
#:
#: * ``R2`` — the catalog already holds the authoritative refusal, named by the
#:   descriptor's own ``MissingMechanism.anchor_fault_id``. Two refusals for one
#:   failure drift, so the existing one stands alone.
#: * ``R3`` — ``NOT_STEPPABLE``: a ``catalog_only`` entry is a promotion ticket,
#:   and CLOCK_MONOTONIC cannot be stepped on Linux at all, so the ticket could
#:   never be redeemed.
#: * ``R4`` — no expressible id. The family prefix is absent from the catalog's
#:   ``_PREFIX_TO_CATEGORY``; adding one means a new ``FaultCategory`` or a
#:   redefinition of ``domain/faults.py``, neither of which this lane owns, and
#:   inventing ``app.jvm_*`` names would be a taxonomy decision nobody asked for.
#: * ``R5a`` — the name an operator would type is occupied by an **active** entry
#:   with a different mechanism (``fs.write_delay`` perturbs write *contention*
#:   from a burner process; it does not delay the target's writes).
#: * ``R5b`` — the catalog has no honest row for the shape: ``io.torn_write`` is
#:   CRITICAL and container-scoped, while the catalog reserves CRITICAL for
#:   pod/node faults.
DESCRIPTOR_ONLY_RULES: Final[Mapping[str, str]] = MappingProxyType(
    {
        "io.read_error": "R2",
        "io.permission_error": "R2",
        "jvm.exception_injection": "R2",
        "clock.realtime_freeze": "R2",
        "clock.monotonic_offset": "R3",
        "clock.monotonic_freeze": "R3",
        "jvm.method_delay": "R4",
        "jvm.return_value_mutation": "R4",
        "jvm.allocation_pressure": "R4",
        "jvm.gc_pressure": "R4",
        "jvm.thread_pressure": "R4",
        "io.torn_write": "R5b",
    }
)

#: The rules above, with what each one says. Printed by the surface so the
#: decision is legible without opening a test file, and checked against the
#: descriptor facts by ``tests/unit/test_lowlevel_refusals.py``.
RULE_IDS: Final[Mapping[str, str]] = MappingProxyType(
    {
        "R2": (
            "the catalog already carries this failure's authoritative catalog_only refusal, so a "
            "second id would be two refusals for one mechanism"
        ),
        "R3": (
            "the operation is not available on this host substrate at all, so a catalog_only row "
            "would be a promotion ticket that could never be redeemed"
        ),
        "R4": (
            "the family prefix is not a registered fault prefix and no FaultCategory is added "
            "here, so there is no id the catalog's own vocabulary produces"
        ),
        "R5a": (
            "the id an operator would type is already an active entry carrying a different "
            "mechanism, so refusing it under that name would misrepresent an entry that works"
        ),
        "R5b": (
            "the catalog reserves the descriptor's risk rung for pod/node scope, so publishing "
            "this would either understate the risk or misfile the scope"
        ),
    }
)

#: Blocked primitives that a refusal already answers for, *and* which also carry a
#: selection rule of their own.
#:
#: ``io.write_delay`` is the only one: it names the same FUSE shim as
#: ``fs.read_delay`` (so that refusal is authoritative and the reader is told
#: where to look) while its own id, ``fs.write_delay``, is occupied by an *active*
#: entry carrying a different mechanism (rule ``R5a``). Recording the second
#: reason is what stops it being lost — a reader who arrives by way of the rule
#: learns that no honest name was free, not merely that one was chosen.
_ADDITIONAL_RULE_BY_PRIMITIVE: Final[Mapping[str, str]] = MappingProxyType(
    {"io.write_delay": "R5a"}
)


class PrimitiveDisposition(StrEnum):
    """What will happen to a primitive, in the four words a person needs.

    The four are genuinely different answers to "can I use this?", which is why
    they are an enum and not a boolean:

    Attributes:
        CARRIED_BY_ACTIVE_FAULT: An **active** catalog entry already injects this
            failure and is named. Nothing here is new: the descriptor documents
            the mechanism that entry uses.
        REFUSED_IN_CATALOG: A ``catalog_only`` entry is the authoritative refusal,
            and it names the missing mechanism.
        DESCRIPTOR_ONLY: No catalog id exists. :data:`DESCRIPTOR_ONLY_RULES` says
            which rule decided that, and the reason is printed.
        UNACHIEVABLE: The host substrate does not offer the operation, so no amount
            of mechanism work closes this. Distinct from "not built yet" on
            purpose, because a roadmap item that can never close is worse than no
            roadmap item.
    """

    CARRIED_BY_ACTIVE_FAULT = "carried_by_active_fault"
    REFUSED_IN_CATALOG = "refused_in_catalog"
    DESCRIPTOR_ONLY = "descriptor_only"
    UNACHIEVABLE = "unachievable"


class PrimitiveAvailability(StrEnum):
    """How much of the mechanism mayhem actually has, in this build.

    Mirrors :class:`mayhem.providers.sandbox.MechanismState` and for the same
    reason: collapsing "mayhem evaluated the policy" and "the operating system
    has been touched" is the whole failure this module exists to prevent. Neither
    member here means "attached".

    Attributes:
        CARRIED_BY_ACTIVE_FAULT: The named active catalog entry's mechanism does
            the work — a real, already-implemented fault, not this module.
        DECLARED_NOT_APPLIED: mayhem computed what would be needed and named it.
            The kernel, the filesystem and the JVM have not been touched.
        UNACHIEVABLE: The operation does not exist on this host. Not a delay in
            the roadmap.
    """

    CARRIED_BY_ACTIVE_FAULT = "carried_by_active_fault"
    DECLARED_NOT_APPLIED = "declared_not_applied"
    UNACHIEVABLE = "unachievable"


# ── the explanation ──────────────────────────────────────────────────────────


class PrimitiveExplanation(BaseModel):
    """Everything a person needs to know about one primitive, in one value.

    :attr:`mechanism_applied` is the field this module exists to keep false, and
    its validator refuses ``True``. Every other field is either read from the
    descriptor or derived from a table above; nothing is editorial.

    Attributes:
        primitive_id: The descriptor's id. Not a fault id.
        title: The descriptor's title.
        family: Which plan-04 family.
        category: The existing ``FaultCategory`` this would be catalogued under.
        risk: The rung it would be catalogued at.
        maturity_floor: The highest maturity it is entitled to claim today.
        injectable: The substrate verdict, recomputed at read time.
        mechanism: The mechanism that would have to exist, named whether or not it
            does. Empty only for a descriptor whose own mechanism is already the
            active fault that carries it.
        mechanism_state: How much of it exists, per :class:`PrimitiveAvailability`.
        mechanism_applied: Always ``False``. Setting it ``True`` is a construction
            error, because the only way to set it honestly is to build the
            mechanism.
        gaps: Every unmet capability demand, in the substrate's stable order.
        limits: Why the mechanism would not be enough on its own — the demands
            outside the impact gate's tables, the privilege, the mount. Never
            empty for a blocked primitive.
        disposition: What will happen, per :class:`PrimitiveDisposition`.
        disposition_reason: One sentence, in words, saying why.
        catalog_fault_id: The catalog id a caller would meet for this primitive,
            when one exists.
        catalog_refusal: That entry's ``refusal_reason``, verbatim, when it is a
            ``catalog_only`` refusal.
        carried_by: The **active** catalog entry already injecting this failure,
            when there is one.
        rule_id: For a descriptor-only primitive, which selection rule decided it.
        rule_reason: What that rule says.
        grammar: The derived parameter grammar. Never empty.
        magnitude_holder: Where the primitive's magnitude lives, in words.
        max_safe_duration_s: The admission bound.
        reversibility: The ladder rung.
        undo: The operation that removes the injection.
        verification: The observation that proves it is gone.
        compensation_template: The ``controller/compensation.py`` template that
            will undo it, or ``None`` for an irreversible primitive.
        residue_checks: ``(facet, probe, expectation)`` triples.
        incompatible_with: Every primitive that cannot be active at the same time,
            read through ``incompatible_ids`` so the relation is symmetric.
        near_misses: Existing ids a reader may mistake for this one. Annotation,
            never a substitute.
        why_no_substitute: Why each near miss is a different failure.
        unachievable_substrate: True when no mechanism on this host can do it.
        notice: :data:`LOWLEVEL_NOT_ATTACHED_NOTICE`, carried on every value so a
            renderer cannot print one without the caveat being available.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    primitive_id: str
    title: str
    family: str
    category: str
    risk: str
    maturity_floor: str
    injectable: bool
    mechanism: str
    mechanism_state: PrimitiveAvailability
    mechanism_applied: bool = False
    gaps: tuple[tuple[str, str], ...] = ()
    limits: tuple[str, ...] = ()
    disposition: PrimitiveDisposition
    disposition_reason: str = Field(min_length=1)
    catalog_fault_id: str | None = None
    catalog_refusal: str | None = None
    carried_by: str | None = None
    rule_id: str | None = None
    rule_reason: str = ""
    grammar: tuple[tuple[str, str], ...] = Field(min_length=1)
    magnitude_holder: str = Field(min_length=1)
    max_safe_duration_s: float
    reversibility: str
    undo: str = Field(min_length=1)
    verification: str = Field(min_length=1)
    compensation_template: str | None = None
    residue_checks: tuple[tuple[str, str, str], ...] = Field(min_length=1)
    incompatible_with: tuple[str, ...] = ()
    near_misses: tuple[str, ...] = ()
    why_no_substitute: str = ""
    unachievable_substrate: bool = False
    notice: str = LOWLEVEL_NOT_ATTACHED_NOTICE

    @model_validator(mode="after")
    def _explanation_is_honest(self) -> PrimitiveExplanation:
        if self.mechanism_applied:
            raise ValueError(
                "mechanism_applied cannot be True: no eBPF loader, FUSE shim, "
                "device-mapper target or JVM agent exists in this build. Setting it "
                "requires the mechanism, not a flag."
            )
        if self.injectable and self.disposition is not PrimitiveDisposition.CARRIED_BY_ACTIVE_FAULT:
            raise ValueError(
                f"{self.primitive_id!r} is injectable on this surface, so its disposition "
                f"must be {PrimitiveDisposition.CARRIED_BY_ACTIVE_FAULT.value!r}"
            )
        if self.carried_by is not None and self.disposition is not (
            PrimitiveDisposition.CARRIED_BY_ACTIVE_FAULT
        ):
            raise ValueError("carried_by is set on a primitive no active fault carries")
        if self.disposition is PrimitiveDisposition.CARRIED_BY_ACTIVE_FAULT and not self.carried_by:
            raise ValueError("a carried primitive must name the active fault that carries it")
        refused = PrimitiveDisposition.REFUSED_IN_CATALOG
        if self.disposition is refused and not self.catalog_fault_id:
            raise ValueError("a catalog refusal must name the catalog id that refuses it")
        if self.rule_id is not None and self.rule_id not in RULE_IDS:
            raise ValueError(f"unknown selection rule {self.rule_id!r}")
        if self.rule_id is not None and not self.rule_reason.strip():
            raise ValueError(f"selection rule {self.rule_id!r} must be stated, not just named")
        unachievable = self.mechanism_state is PrimitiveAvailability.UNACHIEVABLE
        if unachievable and not self.unachievable_substrate:
            raise ValueError(
                "unachievable availability requires the descriptor to say the substrate "
                "itself cannot do it"
            )
        return self

    @property
    def refusal_reason(self) -> str:
        """One sentence an operator can act on: what will happen, and why.

        Composed rather than stored, so it cannot disagree with the fields it
        summarises. A blocked primitive's sentence always names its mechanism: a
        refusal that names nothing gives a reader nothing to file.
        """
        if self.disposition is PrimitiveDisposition.CARRIED_BY_ACTIVE_FAULT:
            return (
                f"{self.primitive_id} is already injected by the active catalog fault "
                f"{self.carried_by}; no new mechanism was built for it."
            )
        if self.disposition is PrimitiveDisposition.REFUSED_IN_CATALOG:
            return (
                f"{self.primitive_id} cannot be injected by this build: "
                f"{self.mechanism} is missing. It is refused in the catalog as "
                f"{self.catalog_fault_id}."
            )
        if self.rule_id is not None:
            return (
                f"{self.primitive_id} cannot be injected by this build: "
                f"{self.mechanism} is missing, and it has no catalog id because "
                f"{self.rule_reason}."
            )
        return (
            f"{self.primitive_id} cannot be injected by this build: "
            f"{self.mechanism} is missing."
        )

    def to_payload(self) -> dict[str, object]:
        """The machine-readable projection, for ``--json`` and any later surface."""
        return {
            "primitive_id": self.primitive_id,
            "title": self.title,
            "family": self.family,
            "category": self.category,
            "risk": self.risk,
            "maturity_floor": self.maturity_floor,
            "injectable": self.injectable,
            "mechanism": self.mechanism,
            "mechanism_state": self.mechanism_state.value,
            "mechanism_applied": self.mechanism_applied,
            "gaps": [{"demand": demand, "reason": reason} for demand, reason in self.gaps],
            "limits": list(self.limits),
            "disposition": self.disposition.value,
            "disposition_reason": self.disposition_reason,
            "refusal_reason": self.refusal_reason,
            "catalog_fault_id": self.catalog_fault_id,
            "catalog_refusal": self.catalog_refusal,
            "carried_by": self.carried_by,
            "rule_id": self.rule_id,
            "rule_reason": self.rule_reason,
            "grammar": [{"name": name, "grammar": grammar} for name, grammar in self.grammar],
            "magnitude_holder": self.magnitude_holder,
            "max_safe_duration_s": self.max_safe_duration_s,
            "reversibility": self.reversibility,
            "undo": self.undo,
            "verification": self.verification,
            "compensation_template": self.compensation_template,
            "residue_checks": [
                {"facet": facet, "probe": probe, "expectation": expectation}
                for facet, probe, expectation in self.residue_checks
            ],
            "incompatible_with": list(self.incompatible_with),
            "near_misses": list(self.near_misses),
            "why_no_substitute": self.why_no_substitute,
            "unachievable_substrate": self.unachievable_substrate,
            "notice": self.notice,
        }


# ── building one ─────────────────────────────────────────────────────────────


def _limits(primitive: LowLevelPrimitive, gaps: tuple[CapabilityGap, ...]) -> tuple[str, ...]:
    """What the mechanism would *still* need after the gaps are closed.

    Derived from the descriptor, and **non-empty for every blocked primitive** —
    the property the validator on :class:`PrimitiveExplanation` relies on. Three
    sources, in the order they bite:

    * each unmet demand, in the substrate's own words, so a reader sees which of
      the three impact-gate traps is in play;
    * ``need_root``, because a uid(0) requirement inside the target is not
      something an agent handshake carries;
    * host-side tools, which the container probe never sees — the trap where a
      demand is real and no in-image check can reach it.
    """
    limits: list[str] = []
    for gap in gaps:
        limits.append(
            f"{gap.demand} is unmet ({gap.reason.value}); "
            f"{_GAP_REASON_TEXT[gap.reason.value]}"
        )
    if primitive.need_root:
        limits.append(
            "the injection needs uid(0) inside the target, which no agent handshake "
            "advertises and which a container's dropped capabilities can remove"
        )
    for tool in sorted(primitive.host_tools - CURRENT_SUBSTRATE.host_tools):
        limits.append(
            f"{tool} is host-side tooling: the in-image probe never sees it, so no "
            "container capability row can report it present"
        )
    if primitive.missing is not None and not primitive.missing.covers_reasons:
        limits.append("the descriptor names no gap the mechanism would close")
    if primitive.missing is not None and primitive.missing.needed_by.strip():
        limits.append(primitive.missing.needed_by)
    return tuple(limits)


_GAP_REASON_TEXT: Final[Mapping[str, str]] = MappingProxyType(
    {
        "bin_not_probed": (
            "the bin is in no _PROBE_BINS row, so the impact gate would report the "
            "fault INERT rather than probe for it"
        ),
        "cap_bit_undefined": (
            "the cap name is in no _CAP_BITS row, so has_cap would return False "
            "unconditionally"
        ),
        "bin_not_installable": (
            "the bin has no _PM_PACKAGES row, so `mayhem prepare dependencies install` "
            "can never supply it"
        ),
        "host_tool_absent": "the host binary is absent and is not probed inside a container",
        "capability_not_offered": (
            "no agent handshake on this surface advertises the capability"
        ),
        "tool_not_manifested": (
            "no toolkit manifest declares the capability in `provides`, so the "
            "capability is not installable as a tool"
        ),
    }
)


def _disposition(
    primitive: LowLevelPrimitive,
) -> tuple[PrimitiveDisposition, str, str | None, str | None]:
    """The disposition, its reason, the catalog id, and the selection rule.

    Derived, in a fixed order, from facts the descriptor already carries and the
    two tables above:

    1. an ``existing_fault_id`` means an **active** catalog entry injects this
       already — the descriptor documents someone else's mechanism;
    2. an ``unachievable_substrate`` means the host does not offer the operation,
       which outranks everything because no table entry can change it;
    3. a row in :data:`CATALOG_REFUSAL_BY_PRIMITIVE` is the authoritative refusal;
    4. otherwise the primitive must carry a row in :data:`DESCRIPTOR_ONLY_RULES``,
       and the absence of one is a *refusal to build the explanation* rather than
       a guess — see :func:`explain_primitive`.
    """
    carried_by = primitive.existing_fault_id
    if carried_by is not None:
        return (
            PrimitiveDisposition.CARRIED_BY_ACTIVE_FAULT,
            f"the active catalog fault {carried_by} already injects this failure; the "
            f"descriptor documents that mechanism rather than adding one",
            None,
            None,
        )
    if primitive.missing is not None and primitive.missing.unachievable_substrate:
        return (
            PrimitiveDisposition.UNACHIEVABLE,
            primitive.missing.why_no_substitute,
            None,
            None,
        )
    fault_id = CATALOG_REFUSAL_BY_PRIMITIVE.get(primitive.id)
    if fault_id is not None:
        return (
            PrimitiveDisposition.REFUSED_IN_CATALOG,
            f"{fault_id} is the catalog_only refusal for {primitive.missing.mechanism}"
            if primitive.missing is not None
            else f"{fault_id} refuses this primitive",
            fault_id,
            None,
        )
    rule_id = DESCRIPTOR_ONLY_RULES.get(primitive.id) or _ADDITIONAL_RULE_BY_PRIMITIVE.get(
        primitive.id
    )
    return (
        PrimitiveDisposition.DESCRIPTOR_ONLY,
        RULE_IDS[rule_id] if rule_id is not None else "",
        None,
        rule_id,
    )


def explain_primitive(
    primitive_id: str, *, surface: SubstrateSurface = CURRENT_SUBSTRATE
) -> PrimitiveExplanation:
    """Explain one primitive, or refuse to.

    The refusal is the load-bearing half. A blocked primitive whose disposition
    cannot be derived from the tables is **not** given a default: it raises
    ``lowlevel.undecided_primitive``. That is what stops this module from
    rendering a new primitive as "descriptor-only, no particular reason" — which
    would read as "we looked and there was nothing to say", the one reading that
    is never right.

    Raises:
        InvariantViolationError: ``lowlevel.unknown_primitive`` when no descriptor
            has this id, and ``lowlevel.undecided_primitive`` when the descriptor
            exists and no rule decides what happens to it.
    """
    primitive = PRIMITIVES.get(primitive_id)
    if primitive is None:
        raise InvariantViolationError(
            "lowlevel.unknown_primitive",
            f"no low-level primitive is declared with id {primitive_id!r}; "
            f"{len(PRIMITIVES)} are declared",
        )
    verdict = primitive.substrate_verdict(surface)
    disposition, reason, catalog_fault_id, rule_id = _disposition(primitive)
    if disposition is PrimitiveDisposition.DESCRIPTOR_ONLY and rule_id is None:
        raise InvariantViolationError(
            "lowlevel.undecided_primitive",
            f"{primitive.id!r} is not injectable on this surface and no row of "
            "CATALOG_REFUSAL_BY_PRIMITIVE or DESCRIPTOR_ONLY_RULES decides what happens "
            "to it. Add the decision rather than rendering an unexplained refusal.",
        )
    missing = primitive.missing
    state = (
        PrimitiveAvailability.CARRIED_BY_ACTIVE_FAULT
        if disposition is PrimitiveDisposition.CARRIED_BY_ACTIVE_FAULT
        else (
            PrimitiveAvailability.UNACHIEVABLE
            if missing is not None and missing.unachievable_substrate
            else PrimitiveAvailability.DECLARED_NOT_APPLIED
        )
    )
    catalog_refusal = (
        definition_for(catalog_fault_id).refusal_reason
        if catalog_fault_id is not None and definition_for(catalog_fault_id).catalog_only
        else None
    )
    return PrimitiveExplanation(
        primitive_id=primitive.id,
        title=primitive.title,
        family=primitive.family.value,
        category=primitive.category.value,
        risk=primitive.risk.value,
        maturity_floor=primitive.maturity_floor.value,
        injectable=verdict.injectable,
        mechanism=missing.mechanism if missing is not None else "",
        mechanism_state=state,
        gaps=tuple((gap.demand, gap.reason.value) for gap in verdict.gaps),
        limits=_limits(primitive, verdict.gaps),
        disposition=disposition,
        disposition_reason=reason,
        catalog_fault_id=catalog_fault_id,
        catalog_refusal=catalog_refusal,
        carried_by=descriptor_for(primitive.id).existing_fault_id,
        rule_id=rule_id,
        rule_reason=RULE_IDS[rule_id] if rule_id is not None else "",
        grammar=tuple((param.name, param.describe()) for param in parameter_grammar(primitive)),
        magnitude_holder=magnitude_holder(primitive),
        max_safe_duration_s=primitive.max_safe_duration_s,
        reversibility=primitive.reversibility_statement.reversibility.value,
        undo=primitive.reversibility_statement.undo,
        verification=primitive.reversibility_statement.verification,
        compensation_template=primitive.reversibility_statement.compensation_template,
        residue_checks=tuple(
            (check.facet.value, check.probe, check.expectation)
            for check in primitive.residue_checks
        ),
        incompatible_with=tuple(sorted(primitive.incompatible_ids())),
        near_misses=tuple(missing.near_misses) if missing is not None else (),
        why_no_substitute=missing.why_no_substitute if missing is not None else "",
        unachievable_substrate=missing.unachievable_substrate if missing is not None else False,
    )


def explain_primitives(
    *, surface: SubstrateSurface = CURRENT_SUBSTRATE
) -> tuple[PrimitiveExplanation, ...]:
    """Every primitive explained, in id order.

    Total: :func:`explain_primitive` either explains or raises, and this one
    propagates the raise rather than skipping an undecided primitive. A listing
    that quietly omitted the one primitive nobody had decided about would be the
    most dishonest output this module could produce.
    """
    return tuple(explain_primitive(pid, surface=surface) for pid in sorted(PRIMITIVES))


def describe_explanation(explanation: PrimitiveExplanation) -> str:
    """Render one explanation as printable lines.

    Split from :func:`describe_primitive` so a surface that already holds an
    explanation renders *that* value rather than re-deriving it — a renderer that
    re-derives can render a different surface's answer than the one in hand.
    """
    lines = [
        f"{explanation.primitive_id} ({explanation.title})",
        f"  family={explanation.family} category={explanation.category} "
        f"risk={explanation.risk} maturity_floor={explanation.maturity_floor}",
        f"  disposition={explanation.disposition.value} "
        f"injectable={str(explanation.injectable).lower()}",
        f"  mechanism={explanation.mechanism or MISSING_MECHANISM_NONE} "
        f"state={explanation.mechanism_state.value} applied="
        f"{str(explanation.mechanism_applied).lower()}",
        f"  verdict: {explanation.refusal_reason}",
    ]
    if explanation.catalog_fault_id:
        lines.append(f"  catalog refusal: {explanation.catalog_refusal}")
    for demand, reason in explanation.gaps:
        lines.append(f"  unmet demand: {demand} ({reason})")
    for limit in explanation.limits:
        lines.append(f"  limit: {limit}")
    lines.append(f"  magnitude: {explanation.magnitude_holder}")
    for name, grammar in explanation.grammar:
        lines.append(f"    - {name}: {grammar}")
    lines.append(
        f"  undo ({explanation.reversibility}): {explanation.undo} -> {explanation.verification}"
    )
    if explanation.compensation_template:
        lines.append(f"  compensation template: {explanation.compensation_template}")
    for facet, probe, expectation in explanation.residue_checks:
        lines.append(f"  residue[{facet}]: {probe} -> {expectation}")
    if explanation.incompatible_with:
        lines.append("  cannot run alongside: " + ", ".join(explanation.incompatible_with))
    if explanation.near_misses:
        lines.append("  not the same fault as: " + ", ".join(explanation.near_misses))
        lines.append(f"    {explanation.why_no_substitute}")
    lines.append(f"  notice: {explanation.notice}")
    return "\n".join(lines)


def describe_primitive(
    primitive_id: str, *, surface: SubstrateSurface = CURRENT_SUBSTRATE
) -> str:
    """One primitive as printable lines, explaining it first.

    Kept beside :func:`explain_primitive` so the vocabulary — the words for a
    disposition, a gap, a residue facet — lives in the domain and not in whichever
    surface happens to print first.
    """
    return describe_explanation(explain_primitive(primitive_id, surface=surface))


# ── the tables, checked against reality ──────────────────────────────────────


def blocked_primitives(*, surface: SubstrateSurface = CURRENT_SUBSTRATE) -> tuple[str, ...]:
    """Every primitive *surface* cannot inject, in id order."""
    return tuple(
        sorted(pid for pid, p in PRIMITIVES.items() if not p.substrate_verdict(surface))
    )


class ConsistencyProblem(BaseModel):
    """One way the two decision tables disagree with the descriptors."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    subject: str
    detail: str


def disposition_problems(
    *, surface: SubstrateSurface = CURRENT_SUBSTRATE
) -> tuple[ConsistencyProblem, ...]:
    """Every disagreement between the tables and the descriptors, as data.

    Pure, total, and deliberately **not** run at import, for the reason
    :func:`mayhem.domain.lowlevel.registry_problems` is not: a table nothing else
    imports must not be able to break ``import mayhem`` the way a non-conforming
    catalog entry breaks the package. Returns the problems instead.

    Five checks, each of which fails in the direction that matters:

    * a blocked primitive in **neither** table is undecided — the surface would
      render a refusal with no reason;
    * a primitive in **both** tables is claimed twice;
    * a table row naming a primitive that is **not** blocked is a refusal for a
      fault that works;
    * a ``catalog_only`` row naming an entry that is **not** ``catalog_only``
      would send a reader to an active fault and call it a refusal;
    * a descriptor-only rule id with no entry in :data:`RULE_IDS` is named and
      not stated.
    """
    problems: list[ConsistencyProblem] = []
    blocked = set(blocked_primitives(surface=surface))
    refused = set(CATALOG_REFUSAL_BY_PRIMITIVE)
    descriptor_only = set(DESCRIPTOR_ONLY_RULES)
    for primitive_id in sorted(blocked - refused - descriptor_only):
        problems.append(
            ConsistencyProblem(
                subject=primitive_id,
                detail="blocked by the substrate and decided by no row of either table",
            )
        )
    for primitive_id in sorted(refused & descriptor_only):
        problems.append(
            ConsistencyProblem(
                subject=primitive_id,
                detail="claimed by both CATALOG_REFUSAL_BY_PRIMITIVE and DESCRIPTOR_ONLY_RULES",
            )
        )
    for primitive_id in sorted((refused | descriptor_only) - blocked):
        problems.append(
            ConsistencyProblem(
                subject=primitive_id,
                detail=(
                    "listed as blocked, but the surface says it is injectable: a refusal "
                    "for a fault that works"
                ),
            )
        )
    for primitive_id, fault_id in sorted(CATALOG_REFUSAL_BY_PRIMITIVE.items()):
        if fault_id not in definition_for(fault_id).id:
            problems.append(
                ConsistencyProblem(subject=primitive_id, detail=f"unknown catalog id {fault_id!r}")
            )
            continue
        if not definition_for(fault_id).catalog_only:
            problems.append(
                ConsistencyProblem(
                    subject=primitive_id,
                    detail=(
                        f"{fault_id!r} is an active catalog entry, so pointing a blocked "
                        "primitive at it as a refusal would send a reader to a fault that works"
                    ),
                )
            )
    for primitive_id, rule_id in sorted(DESCRIPTOR_ONLY_RULES.items()):
        if rule_id not in RULE_IDS:
            problems.append(
                ConsistencyProblem(
                    subject=primitive_id, detail=f"selection rule {rule_id!r} has no stated reason"
                )
            )
    return tuple(problems)
