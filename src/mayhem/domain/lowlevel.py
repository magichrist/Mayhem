"""Low-level primitive descriptors — plan 04 Phase 1 (domain model only).

What this module is
-------------------
A *primitive descriptor* is the admission record for a mechanism that would sit
below the fault catalog: an eBPF kprobe on a syscall, a FUSE/device-mapper shim
on a mount, a JVM instrumentation agent, a clock interception. Phase 1 declares
them as **pure data** — target, mode, scope, capability demand, reversibility,
maximum safe duration, residue checks — so that a mechanism, when it is built in
Phase 2, has to satisfy a contract that already exists instead of inventing one.

What this module is not
-----------------------
It is **not** a mechanism, and it is **not** a catalog entry. Nothing here
injects anything, and nothing here adds a fault id or a ``FaultCategory``:

* Every descriptor **reuses an existing** :class:`~mayhem.domain.faults.FaultCategory`
  via :data:`REUSED_CATEGORY_BY_FAMILY`. A new category is not one line: the
  three TOTAL maps in ``domain/catalog.py`` (``_FAILURE_DOMAIN_BY_CATEGORY``,
  ``_VERIFICATION_BY_CATEGORY``, ``_EFFECT_BY_CATEGORY``) are indexed by
  ``_define`` at import time, so a category missing from any one of them is an
  import-time ``KeyError`` that breaks ``import mayhem`` for the entire package.
* It touches **none** of the five registries a real fault id has to extend
  (catalog definition, executor routing, compensation template, impact
  REQUIREMENTS, deriving tests). The tests below assert that the primitives
  this module declares are *not* fault ids, and that the ones which name an
  existing id (as the already-working mechanism they back) resolve to real,
  active catalog entries.

The honest question
-------------------
Every descriptor must be able to answer one question as a **pure predicate**:
*can the substrate mayhem has today inject this?* :meth:`LowLevelPrimitive.
substrate_verdict` answers it against a :class:`SubstrateSurface` and the answer
is frequently **no**, with a :class:`MissingMechanism` that names what is
missing. Three properties make that answer non-cosmetic:

1. :func:`validate_substrate_claims` refuses a descriptor whose declared
   ``missing`` mechanism does not *cover* every gap today's surface produces —
   and equally refuses one that declares a mechanism as missing when the surface
   says it is satisfiable. Both directions are dishonesty; only the second one is
   usually checked.
2. A primitive that declares a missing mechanism may not claim a maturity
   above ``EXPERIMENTAL``. There is nothing to unit-verify.
3. A :class:`MissingMechanism` has **no field for a substitute**. The
   ``near_misses`` field names existing ids a reader might mistake for this
   primitive and requires a written reason why each is not equivalent — so
   "here is a weaker thing you could use instead" is not expressible. That is
   deliberate: the existing ``catalog_only`` refusals (``clock.freeze``,
   ``fs.read_error``, ``fs.permission_failure``, the OOM class) are
   authoritative, and promoting one requires the mechanism to exist, never a
   weaker stand-in.

Capability demand is checkable, or it is not declared
------------------------------------------------------
A demand a gate cannot evaluate is worse than no demand, because the gate then
answers "impact possible" about a fault that cannot physically take effect.
:data:`CURRENT_SUBSTRATE` restates the three impact-gate tables
(``_PROBE_BINS``, ``_CAP_BITS``, ``_PM_PACKAGES``) and the toolkit's declared
capability vocabulary, and the domain may not import ``mayhem.agents`` — so the
restatement is checked against the real tables by a test rather than by
construction. The three traps that restatement exists to keep visible:

* a bin absent from ``_PROBE_BINS`` is never probed, so the fault gates INERT
  forever (the ``ip`` bug);
* a cap absent from ``_CAP_BITS`` fails ``has_cap`` unconditionally;
* a bin with no ``_PM_PACKAGES`` row can never be auto-installed.

A demand outside those tables is not a silent failure here: it becomes a
:class:`CapabilityGap` with a named reason, and the descriptor has to declare
the matching missing mechanism or be refused.
"""

from __future__ import annotations

import re
from enum import StrEnum
from types import MappingProxyType
from typing import TYPE_CHECKING, Final

from pydantic import BaseModel, ConfigDict, Field, model_validator

from mayhem.domain.capabilities import Capability, Identifier
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.faults import FaultCategory, MaturityLevel, Reversibility
from mayhem.domain.risks import RiskLevel

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping

__all__ = [
    "CURRENT_SUBSTRATE",
    "ERNO_NUMBERS",
    "MAX_SAFE_DURATION_CEILING_S",
    "MIN_MAGNITUDE",
    "PLATFORM_SCOPED_ATTACHMENTS",
    "PRIMITIVES",
    "RETURN_MUTATIONS",
    "REUSED_CATEGORY_BY_FAMILY",
    "SCALING_CLOCK_MODES",
    "SCALING_IO_MODES",
    "SCALING_JVM_MODES",
    "SCALING_KERNEL_MODES",
    "AttachSpecification",
    "CapabilityGap",
    "ClockId",
    "ClockMode",
    "ClockPrimitive",
    "ConsistencyProblem",
    "ErrorCode",
    "GapReason",
    "IOPrimitive",
    "IoMode",
    "IoOperation",
    "IoShim",
    "JVMInstrumentation",
    "JVMPrimitive",
    "JvmInjectionMode",
    "KernelInjectionMode",
    "KernelPrimitive",
    "MissingCode",
    "MissingMechanism",
    "ParamKind",
    "PrimitiveFamily",
    "PrimitiveParam",
    "ResidueCheck",
    "ResidueFacet",
    "ReverseAttachment",
    "ReversibilityStatement",
    "SubstrateSurface",
    "SubstrateVerdict",
    "descriptor_for",
    "injectable_primitives",
    "magnitude_holder",
    "missing_mechanism_for",
    "parameter_grammar",
    "primitive_by_id",
    "registry_problems",
    "resolve_params",
    "specification_for",
    "validate_substrate_claims",
]


# ── capability surfaces ──────────────────────────────────────────────────────


class SubstrateSurface(BaseModel):
    """The substrate, restated as data so the domain can ask it questions.

    A *frozen copy* of what mayhem's runtime can actually see, over four
    independent axes:

    * :attr:`capabilities` — the :class:`~mayhem.domain.capabilities.Capability`
      values a handshake may advertise (``CapabilityReport.capabilities``);
    * :attr:`probe_bins` / :attr:`cap_bits` / :attr:`installable_bins` — the
      three impact-gate tables, by their real names in ``agents/impact.py``;
    * :attr:`host_tools` and :attr:`manifest_capabilities` — host-side binaries
      (``k6``-shaped) and the toolkit's declared capability vocabulary.

    This is deliberately a **second literal that agrees with the first**, not an
    import of it: ``mayhem.domain`` may not depend on ``mayhem.agents`` or
    ``mayhem.toolkit`` (import-linter contract 2), and a dependency that cannot
    be checked is worse than a restatement a test re-checks on every run. If
    either side changes, :data:`CURRENT_SUBSTRATE` and the source table must
    change together — ``tests/unit/test_lowlevel.py`` fails otherwise.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    capabilities: frozenset[Capability] = Field(default_factory=frozenset)
    probe_bins: frozenset[str] = Field(default_factory=frozenset)
    cap_bits: frozenset[str] = Field(default_factory=frozenset)
    installable_bins: frozenset[str] = Field(default_factory=frozenset)
    host_tools: frozenset[str] = Field(default_factory=frozenset)
    manifest_capabilities: frozenset[str] = Field(default_factory=frozenset)

    def is_probed(self, binary: str) -> bool:
        """True when the impact gate would ever report *binary* present."""
        return binary in self.probe_bins

    def has_cap_bit(self, name: str) -> bool:
        """True when ``has_cap`` can evaluate *name* rather than always failing."""
        return name in self.cap_bits

    def is_installable(self, binary: str) -> bool:
        """True when a ``<pm> install`` can supply *binary* from a distro repo."""
        return binary in self.installable_bins

    def is_manifested(self, capability: str) -> bool:
        """True when some tool manifest declares *capability* in ``provides``."""
        return capability in self.manifest_capabilities


#: What mayhem's substrate looks like at this commit. Every field is a restatement
#: of an existing table (see :class:`SubstrateSurface`); none of them is a wish.
#:
#: Note on ``installable_bins`` vs ``probe_bins``: the six package managers are in
#: ``_PROBE_BINS`` (so ``package_manager()`` can find them) but have no
#: ``_PM_PACKAGES`` row, because they are the installer rather than the thing
#: installed. ``k6`` is host-side and is gated with ``host=True``, so it is not
#: probeable inside a container and appears only under :attr:`host_tools`.
CURRENT_SUBSTRATE: Final[SubstrateSurface] = SubstrateSurface(
    capabilities=frozenset(Capability),
    probe_bins=frozenset(
        {
            "kill",
            "tc",
            "ip",
            "iptables",
            "python",
            "python3",
            "date",
            "sh",
            "apt-get",
            "apk",
            "dnf",
            "yum",
            "microdnf",
            "zypper",
        }
    ),
    cap_bits=frozenset({"NET_ADMIN", "SYS_TIME"}),
    installable_bins=frozenset({"python", "ip", "tc", "iptables", "kill", "date", "sh"}),
    host_tools=frozenset({"k6"}),
    manifest_capabilities=frozenset(
        {
            "container.kill",
            "container.pause",
            "container.exec",
            "cpu.pressure",
            "mem.pressure",
            "io.stress",
            "net.latency",
            "net.loss",
            "net.partition",
        }
    ),
)


#: Linux capability-bit name -> the :class:`Capability` a fault declares for it.
#:
#: ``SYS_TIME`` maps to ``NET_ADMIN`` because that is what ``clock.skew``
#: declares today, and this module reuses that choice rather than quietly
#: inventing a ninth ``Capability`` (which would need a handshake, a dashboard
#: row, and a compose ``cap_add:`` path to mean anything). A cap-bit name with
#: no entry here is **not expressible** in a descriptor: declaring it would ask
#: the domain to reason about a capability vocabulary it cannot map, and the
#: right move is a missing mechanism plus a real decision in Phase 2.
_AGENT_CAP_BY_CAP_BIT: Final[Mapping[str, Capability]] = MappingProxyType(
    {
        "NET_ADMIN": Capability.NET_ADMIN,
        "SYS_ADMIN": Capability.SYS_ADMIN,
        "SYS_TIME": Capability.NET_ADMIN,
        "BPF": Capability.SYS_ADMIN,
    }
)


# ── enumerations ─────────────────────────────────────────────────────────────


class PrimitiveFamily(StrEnum):
    """Which plan-04 fault family a descriptor belongs to."""

    KERNEL = "kernel"
    IO = "io"
    JVM = "jvm"
    CLOCK = "clock"


#: The **existing** ``FaultCategory`` each family reuses, and why.
#:
#: Phase 1 adds no category. A bare category is an import-time ``KeyError`` in
#: ``domain/catalog.py`` (three TOTAL maps indexed by ``_define``), and
#: ``tests/unit/test_fault_catalog_exhaustive.py`` additionally asserts
#: category-set equality, so a "harmless" enum member is a package-wide outage.
#: Reusing the category whose failure domain already matches is also the honest
#: answer: a syscall error *is* a process failure, an IO error *is* storage, a
#: clock offset *is* a clock fault, and there is no category for "in-process
#: method perturbation" because "in a process" is ``PROCESS``.
#:
#: ``KERNEL`` is the one mapping a later phase must revisit: a *cgroup- or
#: namespace-scoped* attach perturbs more than one process, so it belongs in
#: ``NODE`` (failure domain ``PLATFORM``). Every kernel primitive declared in
#: this lane is process- or thread-scoped, so ``PROCESS`` is exact today and the
#: descriptor's ``attachment`` field — validated against the category below —
#: is what will force the question when the scope widens.
REUSED_CATEGORY_BY_FAMILY: Final[Mapping[PrimitiveFamily, FaultCategory]] = MappingProxyType(
    {
        PrimitiveFamily.KERNEL: FaultCategory.PROCESS,
        PrimitiveFamily.IO: FaultCategory.STORAGE,
        PrimitiveFamily.JVM: FaultCategory.PROCESS,
        PrimitiveFamily.CLOCK: FaultCategory.CLOCK,
    }
)


class GapReason(StrEnum):
    """Why a declared demand cannot be satisfied by a given surface.

    These are the *names* of the three documented impact-gate traps plus the two
    substrate-level ones, so a gap can be reasoned about without re-deriving it.
    """

    BIN_NOT_PROBED = "bin_not_probed"
    """Bin absent from ``_PROBE_BINS``: never probed, so the fault gates INERT forever."""

    CAP_BIT_UNDEFINED = "cap_bit_undefined"
    """Cap name absent from ``_CAP_BITS``: ``has_cap`` returns False unconditionally."""

    BIN_NOT_INSTALLABLE = "bin_not_installable"
    """Bin has no ``_PM_PACKAGES`` row: reportable, never auto-installable."""

    HOST_TOOL_ABSENT = "host_tool_absent"
    """Host-side binary missing: the container probe never sees it."""

    CAPABILITY_NOT_OFFERED = "capability_not_offered"
    """A ``Capability`` no handshake on this surface advertises."""

    TOOL_NOT_MANIFESTED = "tool_not_manifested"
    """A toolkit capability id no tool manifest declares in ``provides``."""


#: Reason sets a mechanism declaration can account for, named once. A missing
#: mechanism names the set it closes, so the cross-claim check is a real
#: comparison against the reasons the surface actually produced rather than a
#: tautology.
_COVERS_BIN_AND_CAP: Final[frozenset[GapReason]] = frozenset(
    {GapReason.BIN_NOT_PROBED, GapReason.CAP_BIT_UNDEFINED}
)
_COVERS_BIN_AND_TOOL: Final[frozenset[GapReason]] = frozenset(
    {GapReason.BIN_NOT_PROBED, GapReason.TOOL_NOT_MANIFESTED}
)
_COVERS_BIN_CAP_AND_TOOL: Final[frozenset[GapReason]] = frozenset(
    {
        GapReason.BIN_NOT_PROBED,
        GapReason.CAP_BIT_UNDEFINED,
        GapReason.TOOL_NOT_MANIFESTED,
    }
)
_COVERS_TOOL_ONLY: Final[frozenset[GapReason]] = frozenset({GapReason.TOOL_NOT_MANIFESTED})


class MissingCode(StrEnum):
    """Why a mechanism is missing — or why no mechanism would do."""

    MECHANISM_ABSENT = "mechanism_absent"
    """Mayhem has no mechanism; one could be built (Phase 2)."""

    SUBSTRATE_UNPROVISIONED = "substrate_unprovisioned"
    """The mechanism exists in the world but mayhem provisions none of it."""

    NOT_STEPPABLE = "not_steppable"
    """No mechanism can do this: the kernel does not offer the operation.

    Distinct from :attr:`MECHANISM_ABSENT` on purpose. "Mayhem has not built it
    yet" and "the kernel has no such knob" are different answers, and collapsing
    them is how a plan acquires a phase that can never close.
    """


class KernelInjectionMode(StrEnum):
    """What an eBPF/kprobe attach does to a syscall.

    Attributes:
        ERRNO_RETURN: Overwrite the syscall's return value with ``-errno``.
        LATENCY_DELAY: Hold the syscall in-kernel for a bounded window.
        RETURN_MUTATION: Rewrite the return value to a different success value
            (zero a length, cap a count), leaving the call "successful".
    """

    ERRNO_RETURN = "errno_return"
    LATENCY_DELAY = "latency_delay"
    RETURN_MUTATION = "return_mutation"


class ReverseAttachment(StrEnum):
    """What a kernel primitive is attached to.

    The axis that decides blast radius, and therefore which failure domain the
    descriptor may claim.
    """

    PROCESS = "process"
    THREAD = "thread"
    CGROUP = "cgroup"
    NAMESPACE = "namespace"
    MODULE = "module"


#: Attachment scopes that perturb more than the one process they are named
#: against, and therefore map onto ``FailureDomain.PLATFORM`` (``NODE``) rather
#: than ``PROCESS``. Enforced on every kernel descriptor.
PLATFORM_SCOPED_ATTACHMENTS: Final[frozenset[ReverseAttachment]] = frozenset(
    {ReverseAttachment.CGROUP, ReverseAttachment.NAMESPACE, ReverseAttachment.MODULE}
)


class IoOperation(StrEnum):
    """The IO call a primitive perturbs."""

    READ = "read"
    WRITE = "write"
    OPEN = "open"
    FSYNC = "fsync"
    TRUNCATE = "truncate"
    STAT = "stat"
    META = "meta"


class IoMode(StrEnum):
    """How a primitive perturbs an IO call."""

    DELAY = "delay"
    ERROR = "error"
    THROTTLE = "throttle"
    QUOTA = "quota"
    CORRUPT = "corrupt"


class IoShim(StrEnum):
    """The mechanism class that would carry an IO perturbation.

    This is the field that decides honesty. ``MARKER_FILES`` and ``REMOUNT`` are
    things mayhem's substrate can carry today; ``FUSE`` and ``DEVICE_MAPPER``
    need a shim mayhem does not provision, and a descriptor that names one has to
    say so.
    """

    MARKER_FILES = "marker_files"
    REMOUNT = "remount"
    CGROUP_BIO = "cgroup_bio"
    FUSE = "fuse"
    DEVICE_MAPPER = "device_mapper"
    NONE = "none"


class JvmInjectionMode(StrEnum):
    """What a JVM agent does to a target method.

    Attributes:
        METHOD_DELAY: Hold the method's return for a bounded window.
        RETURN_MUTATION: Replace the method's return value.
        EXCEPTION_INJECT: Throw from the method body before it returns.
        ALLOCATION_PRESSURE: Allocate in the target heap to raise GC pressure.
        GC_PRESSURE: Drive the collector without holding a payload.
        THREAD_PRESSURE: Occupy the target's worker pool.
    """

    METHOD_DELAY = "method_delay"
    RETURN_MUTATION = "return_mutation"
    EXCEPTION_INJECT = "exception_inject"
    ALLOCATION_PRESSURE = "allocation_pressure"
    GC_PRESSURE = "gc_pressure"
    THREAD_PRESSURE = "thread_pressure"


class JVMInstrumentation(StrEnum):
    """How a JVM primitive would reach the target VM."""

    JVMTI_AGENT = "jvmti_agent"
    JAVA_INSTRUMENTATION = "java_instrumentation"
    BYTECODE_AGENT = "bytecode_agent"
    HOTSWAP = "hotswap"
    NONE = "none"


class ClockId(StrEnum):
    """Which clock a clock primitive perturbs."""

    REALTIME = "realtime"
    MONOTONIC = "monotonic"
    BOOTTIME = "boottime"
    PROCESS_CPUTIME = "process_cputime"


class ClockMode(StrEnum):
    """How a clock primitive perturbs a clock.

    Attributes:
        OFFSET: Shift the clock by a signed amount.
        RATE: Change the clock's rate (slew), leaving the offset to drift.
        FREEZE: Stop the clock's advance for the target.
    """

    OFFSET = "offset"
    RATE = "rate"
    FREEZE = "freeze"


class ResidueFacet(StrEnum):
    """The thing a residue check has to look at afterwards.

    A check is only a residue check if it is about the world *outside* the
    injector: an attachment left behind, data the target now holds, a clock that
    did not come back. "The inject command exited 0" is not a facet; it is the
    absence of an observation.
    """

    ATTACHMENT = "attachment"
    RETURN_VALUE = "return_value"
    FILESYSTEM = "filesystem"
    INODE_TABLE = "inode_table"
    MOUNT = "mount"
    BYTECODE = "bytecode"
    THREAD_POOL = "thread_pool"
    HEAP = "heap"
    CLOCK = "clock"
    PROCESS_STATE = "process_state"
    CONTAINER = "container"
    CAPABILITY = "capability"


# ── small value types ────────────────────────────────────────────────────────


class ErrorCode(StrEnum):
    """Closed vocabulary of the errno / status a mechanism can produce.

    A closed set on purpose: an arbitrary ``str`` errno invites a typo that
    becomes a silent no-op at injection time, which is the same class of defect
    as the inert ``db.query_error.error`` parameter.
    """

    EPERM = "EPERM"
    EINTR = "EINTR"
    EIO = "EIO"
    ENODEV = "ENODEV"
    EAGAIN = "EAGAIN"
    ENOMEM = "ENOMEM"
    EACCES = "EACCES"
    EBUSY = "EBUSY"
    EEXIST = "EEXIST"
    ENOSPC = "ENOSPC"
    EROFS = "EROFS"
    EPIPE = "EPIPE"
    ERANGE = "ERANGE"
    ENOSYS = "ENOSYS"
    ENOTEMPTY = "ENOTEMPTY"
    EOPNOTSUPP = "EOPNOTSUPP"
    EADDRINUSE = "EADDRINUSE"
    ENETUNREACH = "ENETUNREACH"
    ECONNRESET = "ECONNRESET"
    ENOTCONN = "ENOTCONN"
    ETIMEDOUT = "ETIMEDOUT"
    ECONNREFUSED = "ECONNREFUSED"
    EHOSTUNREACH = "EHOSTUNREACH"
    EDQUOT = "EDQUOT"
    EFBIG = "EFBIG"


#: Linux ``asm-generic`` errno numbers for :class:`ErrorCode`. Present so a
#: mechanism's payload can be written as a number without each builder carrying
#: its own table — and so a wrong number is a wrong *table*, caught by a test,
#: rather than a wrong literal buried in a generated program.
ERNO_NUMBERS: Final[Mapping[ErrorCode, int]] = MappingProxyType(
    {
        ErrorCode.EPERM: 1,
        ErrorCode.EINTR: 4,
        ErrorCode.EIO: 5,
        ErrorCode.ENODEV: 19,
        ErrorCode.EAGAIN: 11,
        ErrorCode.ENOMEM: 12,
        ErrorCode.EACCES: 13,
        ErrorCode.EBUSY: 16,
        ErrorCode.EEXIST: 17,
        ErrorCode.ENOSPC: 28,
        ErrorCode.EROFS: 30,
        ErrorCode.EPIPE: 32,
        ErrorCode.ERANGE: 34,
        ErrorCode.ENOSYS: 38,
        ErrorCode.ENOTEMPTY: 39,
        ErrorCode.EOPNOTSUPP: 95,
        ErrorCode.EADDRINUSE: 98,
        ErrorCode.ENETUNREACH: 101,
        ErrorCode.ECONNRESET: 104,
        ErrorCode.ENOTCONN: 107,
        ErrorCode.ETIMEDOUT: 110,
        ErrorCode.ECONNREFUSED: 111,
        ErrorCode.EHOSTUNREACH: 113,
        ErrorCode.EDQUOT: 122,
        ErrorCode.EFBIG: 27,
    }
)


class ResidueCheck(BaseModel):
    """One observable, taken after the undo, that the world is back.

    Attributes:
        facet: What the check looks at.
        probe: The observation itself, written so a reader can tell whether it
            was actually executed (a command, a log grep, a digest comparison).
        expectation: What a clean undo looks like, including the tolerance.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    facet: ResidueFacet
    probe: str = Field(min_length=1)
    expectation: str = Field(min_length=1)

    @model_validator(mode="after")
    def _not_blank(self) -> ResidueCheck:
        for name in ("probe", "expectation"):
            if not getattr(self, name).strip():
                raise ValueError(f"residue check {name} must not be blank")
        return self


class MissingMechanism(BaseModel):
    """A named reason this primitive cannot be injected, and what would fix it.

    There is deliberately **no substitute field**. The plan's own line is that
    ``clock.freeze``, ``fs.read_error``, ``fs.permission_failure`` and the OOM
    class are not "unimplemented" — promoting one requires the mechanism to
    actually exist, never a weaker stand-in — and a type that can hold a
    substitute is a type that will eventually hold one. :attr:`near_misses`
    records the ids a reader is likely to reach for, together with the reason
    each is *not* the same fault, which is information rather than a fallback.

    Attributes:
        code: Whether the mechanism is unbuilt, unprovisioned, or impossible.
        mechanism: The named thing that is missing.
        needed_by: What a build has to produce for this to become injectable.
        covers_reasons: Which :class:`GapReason` values this mechanism accounts
            for. Explicit rather than implied, so the cross-claim check in
            :func:`validate_substrate_claims` is a real comparison: a descriptor
            that blames an eBPF loader while its only unmet demand is "no manifest
            declares this tool" is refused instead of passing a tautology.
        why_no_substitute: Why an existing id does not stand in for this.
        near_misses: Existing fault ids a reader may mistake for this one. Not
            offered as alternatives; annotated so the resemblance is explicit.
        anchor_fault_id: An existing ``catalog_only`` id whose authoritative
            refusal this primitive's mechanism would have to earn. Empty when
            there is no such refusal to promote.
        unachievable_substrate: True when the host substrate itself cannot do
            this, however much mayhem were built. A descriptor with this set is
            ``NOT_STEPPABLE``-shaped and will never become injectable on Linux.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    code: MissingCode = MissingCode.MECHANISM_ABSENT
    mechanism: str = Field(min_length=3)
    needed_by: str = Field(min_length=3)
    covers_reasons: frozenset[GapReason] = Field(min_length=1)
    why_no_substitute: str = Field(min_length=20)
    near_misses: tuple[str, ...] = ()
    anchor_fault_id: str | None = None
    unachievable_substrate: bool = False

    @model_validator(mode="after")
    def _consistent(self) -> MissingMechanism:
        if not self.mechanism.strip() or not self.needed_by.strip():
            raise ValueError("missing-mechanism fields must not be blank")
        if self.unachievable_substrate and self.code is not MissingCode.NOT_STEPPABLE:
            raise ValueError("an unachievable substrate must be declared NOT_STEPPABLE")
        if len(set(self.near_misses)) != len(self.near_misses):
            raise ValueError("near-miss fault ids must be unique")
        if self.anchor_fault_id == "":
            raise ValueError("anchor_fault_id must be a fault id or null, not an empty string")
        return self

    def covers(self, gap: CapabilityGap) -> bool:
        """True when this declaration accounts for *gap*.

        By :attr:`covers_reasons` rather than by demand string, so a mechanism
        that provisions an eBPF loader accounts for every bin and cap-bit gap the
        loader was blocking, and enumerating them one by one cannot make the
        declaration quietly wrong when the gate grows a column. It is still a
        comparison rather than a tautology: a gap whose reason the declaration
        does not list is not covered, which is what
        :func:`validate_substrate_claims` refuses.
        """
        return gap.reason in self.covers_reasons


class ReversibilityStatement(BaseModel):
    """How a primitive comes back, in one required object.

    The three fields are one statement: the ladder rung, the operation that
    removes the injection, and the observation that proves it is gone. Requiring
    the object (rather than a bare ``reversibility`` flag) is what makes "no
    reversibility statement" a construction error naming the field, instead of a
    descriptor that looks safe because it defaulted to ``True``.

    ``compensation_template`` is the Phase-2 contract in advance: a
    non-irreversible primitive must name the ``controller/compensation.py``
    template that will undo it, and an **irreversible** primitive must not claim
    one. The planner refuses a fault whose template yields zero undo ops, so a
    template claimed here is a promise the code has to keep.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    reversibility: Reversibility
    undo: str = Field(min_length=1)
    verification: str = Field(min_length=1)
    compensation_template: str | None = None
    reconciliation: str = ""

    @model_validator(mode="after")
    def _statement_is_present(self) -> ReversibilityStatement:
        for name in ("undo", "verification"):
            if not getattr(self, name).strip():
                raise ValueError(f"reversibility_statement.{name} must not be blank")
        if self.reversibility is Reversibility.IRREVERSIBLE:
            if self.compensation_template is not None:
                raise ValueError(
                    "an irreversible primitive cannot claim a compensation template: "
                    "there is nothing for it to undo"
                )
            if not self.reconciliation.strip():
                raise ValueError("an irreversible primitive must state what reconciles it")
        elif self.compensation_template is None:
            raise ValueError(
                f"a {self.reversibility.value} primitive must name its compensation template"
            )
        if self.compensation_template is not None and not self.compensation_template.strip():
            raise ValueError("compensation_template must not be blank")
        return self


class CapabilityGap(BaseModel):
    """One declared demand the given surface cannot satisfy.

    Attributes:
        demand: The demand in impact-gate vocabulary — ``bin:``, ``cap:``,
            ``host_tool:``, ``capability:`` or ``tool:``.
        reason: Which of the documented traps this is.
        mechanism_id: The missing mechanism that would close it, or ``""`` when
            the descriptor has not named one (which is a refusal, not a detail).
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    demand: str = Field(min_length=3)
    reason: GapReason
    mechanism_id: str = ""


class SubstrateVerdict(BaseModel):
    """The pure answer to "can today's substrate inject this?".

    Attributes:
        primitive_id: Which primitive was asked about.
        injectable: The predicate's whole answer. A gap set means ``False``.
        gaps: Every unsatisfied demand, in a stable order.
        detail: One sentence naming the reason, safe to print.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    primitive_id: str
    injectable: bool
    gaps: tuple[CapabilityGap, ...] = ()
    detail: str = ""

    def __bool__(self) -> bool:
        return self.injectable


# ── descriptors ──────────────────────────────────────────────────────────────

_SYSCALL_RE: Final[re.Pattern[str]] = re.compile(r"^[a-z][a-z0-9_]{1,31}$")
_JVM_CLASS_RE: Final[re.Pattern[str]] = re.compile(
    r"^(?:[a-zA-Z_$][a-zA-Z0-9_$]*\.)*[a-zA-Z_$][a-zA-Z0-9_$]*$"
)
_JVM_METHOD_RE: Final[re.Pattern[str]] = re.compile(r"^[a-zA-Z_$][a-zA-Z0-9_$<>]*$")
_JVM_EXCEPTION_RE: Final[re.Pattern[str]] = re.compile(
    r"^(?:[a-zA-Z_$][a-zA-Z0-9_$]*\.)+[A-Za-z_$][A-Za-z0-9_$]*(?:Exception|Error|Throwable)$"
)
_RETURN_MUTATIONS: Final[frozenset[str]] = frozenset(
    {"zero", "max", "increment", "decrement", "mask_high_bit", "saturate"}
)

#: Public alias for the mutation vocabulary. The descriptor validator refuses a
#: mutation outside this set and the parameter grammar builds its ``choices``
#: from it, so the closed vocabulary has exactly one definition — a second copy
#: in the grammar would be a second thing to keep in step.
RETURN_MUTATIONS: Final[frozenset[str]] = _RETURN_MUTATIONS


#: What one ``pressure_units`` means per mode. Named because a bare number next
#: to a JVM primitive is unreadable: 262144 is 256 KiB of allocation and also a
#: quarter of a million GC requests, and those are not interchangeable.
class _PressureUnit(StrEnum):
    BYTES = "bytes"
    INVOCATIONS = "invocations"
    THREADS = "threads"


_PRESSURE_UNITS: Final[Mapping[JvmInjectionMode, _PressureUnit]] = MappingProxyType(
    {
        JvmInjectionMode.ALLOCATION_PRESSURE: _PressureUnit.BYTES,
        JvmInjectionMode.GC_PRESSURE: _PressureUnit.INVOCATIONS,
        JvmInjectionMode.THREAD_PRESSURE: _PressureUnit.THREADS,
    }
)
#: Linux's usable slew range for a clock frequency, in parts per million.
#: Outside it ``adjtimex`` refuses or clamps, which would make the injected fault
#: a different fault from the declared one — so the bound is refused here rather
#: than discovered as a silently-wrong offset at injection time.
MAX_SLEW_PPM: Final[int] = 500
#: The bound the catalog already enforces (``catalog.validate_catalog``): a
#: HIGH or CRITICAL fault may not declare a window wider than this. Reused as a
#: domain constant rather than a second number with a second meaning.
MAX_SAFE_DURATION_CEILING_S: Final[float] = 600.0

#: The floor on a magnitude. A zero magnitude injects nothing, which is the
#: inert-parameter defect in its purest form: the fault is accepted, the plan
#: records it, and nothing happens. Unrepresentable rather than defaulted.
MIN_MAGNITUDE: Final[int] = 1

#: The ceiling on a JVM pressure magnitude, in whatever unit the mode reads.
#: Not a duration and deliberately not :data:`MAX_SAFE_DURATION_CEILING_S`: a
#: GC-pressure count of 10^9 invocations is not a longer fault than one of 10^6,
#: it is a different fault, and the bound exists so the *shape* of the pressure
#: is a decision rather than an accident. Phase 3's decision, recorded because
#: the alternative — inheriting the duration ceiling — would silently permit an
#: allocation size large enough to OOM a heap that is not the point.
_MAX_PRESSURE_UNITS: Final[float] = 1_000_000.0


def _magnitude_is_declared(
    *,
    declared: int | None,
    required: bool,
    field: str,
    ceiling_ms: float,
    mode: str,
) -> None:
    """One rule for every tunable mode, so a mode cannot ship without a size.

    Three checks, and the first is the one that catches a real defect: a mode
    that *perturbs by an amount* must declare *how much*, because a delay fault
    whose only parameter is "on or off" cannot be told apart from a no-op by an
    observer, by a residue check, or by a reviewer reading the plan. The second
    refuses a magnitude no mechanism could honour — a latency longer than the
    descriptor's own maximum safe duration is not a more aggressive fault, it is
    a fault whose recovery may never run. The third refuses a magnitude a
    non-magnitude mode has no use for, because an unused field is a field that
    later gets set by accident.
    """
    if required and declared is None:
        raise ValueError(
            f"{mode} mode must declare {field}: a perturbation with no magnitude is "
            "a fault that cannot differ from a no-op"
        )
    if not required and declared is not None:
        raise ValueError(f"{mode} mode perturbs by no magnitude, so it declares no {field}")
    if declared is None:
        return
    if declared < MIN_MAGNITUDE:
        raise ValueError(f"{field} must be at least {MIN_MAGNITUDE}: zero injects nothing")
    if float(declared) > ceiling_ms:
        raise ValueError(
            f"{field}={declared}ms exceeds the descriptor's own maximum safe duration of "
            f"{ceiling_ms:g}ms: a fault that outlasts its own recovery window cannot be undone"
        )


class LowLevelPrimitive(BaseModel):
    """Base descriptor: admission metadata for one low-level mechanism.

    Subclasses add the target and mode; everything an admission decision needs —
    capability demand, reversibility, maximum safe duration, residue checks,
    compatibility, and the missing-mechanism declaration — lives here so the
    refusal rules are written once.

    Attributes:
        id: Dotted identifier. **Not** a fault id: nothing routes on it, nothing
            compensates it, and ``domain/catalog.py`` does not know it exists.
        family: Which plan-04 family, which fixes the reused category.
        category: The **existing** ``FaultCategory`` this primitive would be
            catalogued under. Constrained to :data:`REUSED_CATEGORY_BY_FAMILY`.
        risk: The rung a mechanism would be catalogued at if it existed.
        maturity_floor: The highest maturity this descriptor is entitled to
            claim *today*. A primitive with a missing mechanism is capped at
            ``EXPERIMENTAL``: there is no mechanism to unit-verify.
        max_safe_duration_s: The admission bound. Mirrors the catalog's rule
            that HIGH/CRITICAL may not exceed 600 s.
        required_caps: Agent capabilities a handshake must advertise.
        probe_bins: In-container binaries the impact gate would have to probe.
        probe_caps: Linux capability-bit names the gate would have to evaluate.
        need_root: The injection needs uid(0) inside the target.
        host_tools: Host-side binaries (gated with ``host=True``; the container
            probe and ``mayhem prepare dependencies install`` never see these).
        tool_capabilities: Toolkit capability ids (``toolkit/manifests/*.yaml``
            ``provides``) that some manifest must declare for this primitive.
        residue_checks: Non-empty. What to look at after the undo.
        incompatible_with: Other primitive ids that must not be active at the
            same time because the observation could not be attributed. The
            relation is read through :meth:`incompatible_ids`, which is
            symmetric by construction, so a pair only has to be written down
            once.
        existing_fault_id: The active catalog entry whose mechanism already
            backs this primitive, when one does. This is a **reference**, not an
            id: the tests resolve it through ``catalog.definition_for`` and
            require it to exist and to be non-``catalog_only``.
        missing: The honest answer when today's substrate cannot inject this.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: Identifier
    family: PrimitiveFamily
    mode: object = Field(exclude=True)
    """The family's own mode enum, declared on the base so a family-agnostic
    reader can dispatch on it. Subclasses narrow it to their own enum, which is
    why :func:`_magnitude_field` and :func:`_mode_of` can read it without an
    ``isinstance`` chain — and why a family that forgot to declare one fails at
    construction rather than at injection time."""
    title: str = Field(min_length=4)
    summary: str = Field(min_length=20)
    category: FaultCategory
    risk: RiskLevel
    maturity_floor: MaturityLevel = MaturityLevel.EXPERIMENTAL
    max_safe_duration_s: float = Field(gt=0.0)
    required_caps: frozenset[Capability] = Field(default_factory=frozenset)
    probe_bins: frozenset[str] = Field(default_factory=frozenset)
    probe_caps: frozenset[str] = Field(default_factory=frozenset)
    need_root: bool = False
    host_tools: frozenset[str] = Field(default_factory=frozenset)
    tool_capabilities: frozenset[str] = Field(default_factory=frozenset)
    reversibility_statement: ReversibilityStatement
    residue_checks: tuple[ResidueCheck, ...] = Field(min_length=1)
    incompatible_with: frozenset[Identifier] = Field(default_factory=frozenset)
    existing_fault_id: str | None = None
    missing: MissingMechanism | None = None
    notes: str = ""

    @model_validator(mode="after")
    def _descriptor_is_admissible(self) -> LowLevelPrimitive:
        if not self.title.strip() or not self.summary.strip():
            raise ValueError("a primitive must have a title and a summary")
        if self.id in self.incompatible_with:
            raise ValueError(f"primitive {self.id!r} cannot be incompatible with itself")
        if self.existing_fault_id == "":
            raise ValueError("existing_fault_id must be a fault id or null")
        if (
            self.risk.at_least(RiskLevel.HIGH)
            and self.max_safe_duration_s > MAX_SAFE_DURATION_CEILING_S
        ):
            raise ValueError(
                f"{self.risk.value} primitive must not exceed "
                f"{MAX_SAFE_DURATION_CEILING_S:g}s of maximum safe duration"
            )
        expected = REUSED_CATEGORY_BY_FAMILY[self.family]
        if self.category is not expected:
            raise ValueError(
                f"{self.family.value} primitives reuse category {expected.value!r}; "
                f"{self.category.value!r} would be a new category, which plan 04 "
                f"Phase 1 does not add"
            )
        self._validate_capability_demands()
        self._validate_missing_claim()
        return self

    def _validate_capability_demands(self) -> None:
        """A demand the gate cannot evaluate, or cannot be spoken for, is refused.

        Only one rule lives here, and it is the one that cannot be satisfied by
        naming a capability at random: a Linux cap-bit name has to map onto a
        :class:`Capability` the descriptor also declares, so ``probe_caps`` and
        ``required_caps`` can never drift apart. In-image tooling deliberately
        demands *no* agent capability — ``fs.fill`` needs a ``python`` binary and
        no handshake flag — so a primitive with ``probe_bins`` and an empty
        ``required_caps`` is correct, not incomplete.
        """
        unmapped = sorted(self.probe_caps - set(_AGENT_CAP_BY_CAP_BIT))
        if unmapped:
            raise ValueError(
                "probe_caps must map to a declared Capability; unmapped: " + ", ".join(unmapped)
            )
        for cap_bit in sorted(self.probe_caps):
            agent_cap = _AGENT_CAP_BY_CAP_BIT[cap_bit]
            if agent_cap not in self.required_caps:
                raise ValueError(
                    f"probe cap {cap_bit!r} maps to {agent_cap.value!r}, which the "
                    f"descriptor does not declare in required_caps"
                )

    def _validate_missing_claim(self) -> None:
        """A missing-mechanism declaration has to be consistent with itself.

        Three rules, and the third is the one that stops a roadmap item from
        being filed for an operation the kernel does not offer: an impossible
        operation is not "not built yet".
        """
        if self.missing is None:
            return
        if self.maturity_floor is not MaturityLevel.EXPERIMENTAL:
            raise ValueError(
                "a primitive with a missing mechanism cannot claim a maturity "
                "above experimental: there is no mechanism to verify"
            )
        if self.existing_fault_id is not None:
            raise ValueError(
                "a primitive that names an existing active fault has a working "
                "mechanism and cannot also declare one missing"
            )
        unachievable = self.missing.unachievable_substrate
        if unachievable and self.missing.code is not MissingCode.NOT_STEPPABLE:
            raise ValueError("an unachievable substrate must be declared NOT_STEPPABLE")

    # -- the pure predicate ----------------------------------------------------

    def incompatible_ids(self) -> frozenset[str]:
        """Every primitive that cannot be active alongside this one.

        Symmetric by construction: the union of what this descriptor declares and
        what the other side declares. Making the relation derived rather than
        requiring both sides to repeat each other removes the one class of
        authoring mistake a collision graph cannot afford — a rule that reads
        two ways because only one side wrote it down. Callers building the 07
        collision graph read this, not the field.
        """
        reverse = {other.id for other in PRIMITIVES.values() if self.id in other.incompatible_with}
        return frozenset(self.incompatible_with | reverse) - {self.id}

    def substrate_gaps(self, surface: SubstrateSurface) -> tuple[CapabilityGap, ...]:
        """Every demand *surface* cannot satisfy, in a stable order.

        The order is fixed — agent capabilities, unprobeable bins, undefined cap
        bits, probeable-but-uninstallable bins, missing host tools, unmanifested
        tool capabilities — so two runs of the same descriptor against the same
        surface produce byte-identical output, which is what makes a verdict
        citable in evidence.
        """
        gaps: list[CapabilityGap] = []
        for cap in sorted(self.required_caps - surface.capabilities, key=lambda c: c.value):
            gaps.append(
                CapabilityGap(
                    demand=f"capability:{cap.value}",
                    reason=GapReason.CAPABILITY_NOT_OFFERED,
                    mechanism_id=self._mechanism_id(),
                )
            )
        for binary in sorted(self.probe_bins):
            if not surface.is_probed(binary):
                gaps.append(
                    CapabilityGap(
                        demand=f"bin:{binary}",
                        reason=GapReason.BIN_NOT_PROBED,
                        mechanism_id=self._mechanism_id(),
                    )
                )
        for cap_bit in sorted(self.probe_caps):
            if surface.has_cap_bit(cap_bit):
                continue
            gaps.append(
                CapabilityGap(
                    demand=f"cap:{cap_bit}",
                    reason=GapReason.CAP_BIT_UNDEFINED,
                    mechanism_id=self._mechanism_id(),
                )
            )
        for binary in sorted(self.probe_bins):
            if surface.is_probed(binary) and not surface.is_installable(binary):
                gaps.append(
                    CapabilityGap(
                        demand=f"bin:{binary}",
                        reason=GapReason.BIN_NOT_INSTALLABLE,
                        mechanism_id=self._mechanism_id(),
                    )
                )
        for binary in sorted(self.host_tools - surface.host_tools):
            gaps.append(
                CapabilityGap(
                    demand=f"host_tool:{binary}",
                    reason=GapReason.HOST_TOOL_ABSENT,
                    mechanism_id=self._mechanism_id(),
                )
            )
        for capability in sorted(self.tool_capabilities):
            if surface.is_manifested(capability):
                continue
            gaps.append(
                CapabilityGap(
                    demand=f"tool:{capability}",
                    reason=GapReason.TOOL_NOT_MANIFESTED,
                    mechanism_id=self._mechanism_id(),
                )
            )
        return tuple(gaps)

    def substrate_verdict(self, surface: SubstrateSurface = CURRENT_SUBSTRATE) -> SubstrateVerdict:
        """Can *surface* inject this primitive, right now?

        Pure and total. The answer is ``False`` whenever any declared demand is
        unmet, and the gaps say which — including the three impact-gate traps,
        which is the whole reason a demand has to be checkable in the first
        place.
        """
        gaps = self.substrate_gaps(surface)
        if not gaps:
            return SubstrateVerdict(
                primitive_id=self.id,
                injectable=True,
                detail=(
                    f"{self.id} is injectable on this surface: every demand it "
                    f"declares is probeable, evaluable and manifest-declared"
                ),
            )
        first = gaps[0]
        return SubstrateVerdict(
            primitive_id=self.id,
            injectable=False,
            gaps=gaps,
            detail=(
                f"{self.id} is not injectable on this surface: {len(gaps)} unmet "
                f"demand(s), first is {first.demand} ({first.reason.value})"
            ),
        )

    def _mechanism_id(self) -> str:
        return self.missing.mechanism if self.missing is not None else ""


class KernelPrimitive(LowLevelPrimitive):
    """A syscall-level perturbation: what to hook, how, and where.

    Attributes:
        syscalls: The syscalls the attach matches on. Non-empty; the names are
            ``sys(2)``-shaped and are **not** validated against a syscall table
            here — a name the kernel does not have would fail at load time, and
            a Phase-2 loader is the right place to say so.
        mode: errno return, latency, or return mutation.
        attachment: The blast-radius axis. ``CGROUP``/``NAMESPACE``/``MODULE``
            are refused on a ``PROCESS`` category, because they are not.
        errno_name: Required iff ``mode`` is ``ERRNO_RETURN``.
        return_mutation: Required iff ``mode`` is ``RETURN_MUTATION``.
        latency_ms: Required iff ``mode`` is ``LATENCY_DELAY``, and bounded by the
            descriptor's own ``max_safe_duration_s``. Phase 3 added it: a latency
            mode with no magnitude is a fault that cannot differ from itself, which
            is the inert-parameter defect the Phase-5 regression guard exists to
            make impossible.
        loader: The loader class a Phase-2 mechanism would register.
    """

    syscalls: frozenset[str] = Field(min_length=1)
    mode: KernelInjectionMode
    attachment: ReverseAttachment = ReverseAttachment.PROCESS
    errno_name: ErrorCode | None = None
    return_mutation: str | None = None
    latency_ms: int | None = None
    loader: str = Field(min_length=3)

    @model_validator(mode="after")
    def _mode_is_complete(self) -> KernelPrimitive:
        bad = sorted(name for name in self.syscalls if _SYSCALL_RE.fullmatch(name) is None)
        if bad:
            raise ValueError("syscall names must be lowercase identifiers: " + ", ".join(bad))
        if self.mode is KernelInjectionMode.ERRNO_RETURN and self.errno_name is None:
            raise ValueError("errno_return mode must name the errno it returns")
        if self.mode is not KernelInjectionMode.ERRNO_RETURN and self.errno_name is not None:
            raise ValueError(f"{self.mode.value} mode returns no errno")
        if self.mode is KernelInjectionMode.RETURN_MUTATION:
            if self.return_mutation not in _RETURN_MUTATIONS:
                raise ValueError(
                    "return_mutation must be one of: " + ", ".join(sorted(_RETURN_MUTATIONS))
                )
        elif self.return_mutation is not None:
            raise ValueError(f"{self.mode.value} mode mutates no return value")
        _magnitude_is_declared(
            declared=self.latency_ms,
            required=self.mode is KernelInjectionMode.LATENCY_DELAY,
            field="latency_ms",
            ceiling_ms=self.max_safe_duration_s * 1000.0,
            mode=self.mode.value,
        )
        if self.attachment in PLATFORM_SCOPED_ATTACHMENTS:
            raise ValueError(
                f"{self.attachment.value}-scoped attaches perturb more than one "
                f"process and belong to FaultCategory.NODE; plan 04 Phase 1 "
                f"reuses PROCESS and declares only process/thread-scoped attaches"
            )
        return self


class IOPrimitive(LowLevelPrimitive):
    """An IO-path perturbation: which call, which path, carried by what.

    Attributes:
        operation: The IO call perturbed.
        mode: delay, error, throttle, quota, or corrupt.
        shim: The mechanism class. ``MARKER_FILES`` and ``REMOUNT`` are things
            mayhem's substrate carries; the rest are declarations of absence.
        path_param: The *name* of the fault parameter carrying the affected
            path — a name, not a path, so it is identifier-shaped.
        default_path: The absolute path the primitive defaults to. Absolute for
            the same reason ``fs.fill``'s compensation refuses a relative one:
            a relative path resolves against whatever cwd the executor happens
            to run with, which is not a target the operator chose.
        error_code: The errno returned, iff ``mode`` is ``ERROR``.
        delay_ms: Required iff ``mode`` is ``DELAY``, and bounded by the
            descriptor's own ``max_safe_duration_s``. Phase 3 added it for the
            reason :func:`_magnitude_is_declared` gives.
    """

    operation: IoOperation
    mode: IoMode
    shim: IoShim
    path_param: Identifier
    default_path: str = Field(min_length=1)
    error_code: ErrorCode | None = None
    delay_ms: int | None = None

    @model_validator(mode="after")
    def _io_is_well_formed(self) -> IOPrimitive:
        if not self.default_path.startswith("/"):
            raise ValueError("default_path must be an absolute path")
        if self.mode is IoMode.ERROR and self.error_code is None:
            raise ValueError("error mode must name the errno it returns")
        if self.mode is not IoMode.ERROR and self.error_code is not None:
            raise ValueError(f"{self.mode.value} mode returns no errno")
        _magnitude_is_declared(
            declared=self.delay_ms,
            required=self.mode is IoMode.DELAY,
            field="delay_ms",
            ceiling_ms=self.max_safe_duration_s * 1000.0,
            mode=self.mode.value,
        )
        if self.shim in {IoShim.MARKER_FILES, IoShim.REMOUNT, IoShim.NONE} and (
            self.missing is not None
        ):
            # These three shims are the ones mayhem's substrate already carries.
            # Declaring a mechanism missing for one of them would make the
            # descriptor untrustworthy in the other direction, so it is refused
            # here rather than argued about in review.
            raise ValueError(
                f"shim {self.shim.value!r} is provisioned by mayhem's current "
                f"substrate; it cannot declare a missing mechanism"
            )
        return self


class JVMPrimitive(LowLevelPrimitive):
    """An in-JVM perturbation: which method, which mode, carried by what.

    Attributes:
        target_class: Fully-qualified class name the attach instruments.
        target_method: Method name on that class.
        instrumentation: The agent class a Phase-2 mechanism would register.
        mode: What the agent does to the method.
        exception_class: Required iff ``mode`` is ``EXCEPTION_INJECT``.
        delay_ms: Required iff ``mode`` is ``METHOD_DELAY``. The same rule as the
            other families' magnitudes: a method-delay agent with no delay is a
            no-op that still attaches, which is the worst shape — residue with no
            fault.
        pressure_units: Required for every *pressure* mode, read per mode:
            allocation bytes for ``ALLOCATION_PRESSURE``, invocation count for
            ``GC_PRESSURE``, threads for ``THREAD_PRESSURE``. One field rather
            than three because the mode says which it is, and a field the mode
            has to disambiguate is a field a mechanism can misread.
        jvm_version_range: The JVM versions the descriptor claims to hold for.
    """

    target_class: str = Field(min_length=1)
    target_method: str = Field(min_length=1)
    instrumentation: JVMInstrumentation
    mode: JvmInjectionMode
    exception_class: str | None = None
    delay_ms: int | None = None
    pressure_units: int | None = None
    jvm_version_range: str = ""

    @model_validator(mode="after")
    def _jvm_is_well_formed(self) -> JVMPrimitive:
        if _JVM_CLASS_RE.fullmatch(self.target_class) is None:
            raise ValueError("target_class must be a dotted Java class name")
        if _JVM_METHOD_RE.fullmatch(self.target_method) is None:
            raise ValueError("target_method must be a Java method name")
        if self.mode is JvmInjectionMode.EXCEPTION_INJECT:
            if self.exception_class is None:
                raise ValueError("exception_inject mode must name the exception class")
            if _JVM_EXCEPTION_RE.fullmatch(self.exception_class) is None:
                raise ValueError(
                    "exception_class must be a fully-qualified Throwable subclass name"
                )
        elif self.exception_class is not None:
            raise ValueError(f"{self.mode.value} mode injects no exception")
        _magnitude_is_declared(
            declared=self.delay_ms,
            required=self.mode is JvmInjectionMode.METHOD_DELAY,
            field="delay_ms",
            ceiling_ms=self.max_safe_duration_s * 1000.0,
            mode=self.mode.value,
        )
        _magnitude_is_declared(
            declared=self.pressure_units,
            required=self.mode
            in {
                JvmInjectionMode.ALLOCATION_PRESSURE,
                JvmInjectionMode.GC_PRESSURE,
                JvmInjectionMode.THREAD_PRESSURE,
            },
            field="pressure_units",
            # A pressure magnitude is not a duration: the bound is the absolute
            # units cap, and reusing the duration ceiling here would let a
            # descriptor declare a 300-second allocation of 600 MiB.
            ceiling_ms=_MAX_PRESSURE_UNITS,
            mode=self.mode.value,
        )
        return self


class ClockPrimitive(LowLevelPrimitive):
    """A clock perturbation: which clock, which mode, by how much.

    Attributes:
        clock_id: The clock perturbed.
        mode: offset, rate (slew), or freeze.
        offset_ms: Required iff ``mode`` is ``OFFSET``, and non-zero. A
            zero-offset clock fault is a fault that injects nothing — the inert
            parameter class — so it is unrepresentable rather than defaulted.
        rate_ppm: Required iff ``mode`` is ``RATE``. Linux slews a monotonic
            clock by frequency, and the kernel clamps the usable range; a ppm
            figure outside the representable range would be silently clamped by
            ``adjtimex`` and produce a fault that is not the one that was asked
            for, so the bound is stated here rather than discovered at runtime.
        scoped_to_process: True when only the target's view of the clock moves.
    """

    clock_id: ClockId
    mode: ClockMode
    offset_ms: int | None = None
    rate_ppm: int | None = None
    scoped_to_process: bool = False

    @model_validator(mode="after")
    def _clock_is_well_formed(self) -> ClockPrimitive:
        if self.mode is ClockMode.OFFSET:
            if self.offset_ms is None:
                raise ValueError("offset mode must declare the offset it applies")
            if self.offset_ms == 0:
                raise ValueError("a zero clock offset injects nothing")
            if self.rate_ppm is not None:
                raise ValueError("offset mode sets no rate")
        elif self.mode is ClockMode.RATE:
            if self.rate_ppm is None:
                raise ValueError("rate mode must declare the ppm it applies")
            if abs(self.rate_ppm) > MAX_SLEW_PPM:
                raise ValueError(
                    f"rate_ppm outside the kernel's usable slew range (+/-{MAX_SLEW_PPM} ppm)"
                )
            if self.offset_ms is not None:
                raise ValueError("rate mode sets no offset")
        elif self.offset_ms is not None or self.rate_ppm is not None:
            raise ValueError("freeze mode changes neither offset nor rate")
        return self


# ── the declared primitive set ───────────────────────────────────────────────

#: Every primitive Phase 1 declares, keyed by id.
#:
#: 22 descriptors, of which **four** the current substrate can inject and
#: eighteen it cannot. The four are not new mechanisms: they are the existing
#: ``fs.fill``, ``fs.inode_exhaust``, ``fs.read_only`` and ``clock.skew`` families
#: described from below, and each names the catalog id that already carries it.
#: The eighteen name what is missing. Nothing here is executable and nothing
#: here is a fault id.
PRIMITIVES: Final[Mapping[str, LowLevelPrimitive]] = MappingProxyType(
    {
        primitive.id: primitive
        for primitive in (
            KernelPrimitive(
                id="kernel.syscall_errno",
                family=PrimitiveFamily.KERNEL,
                title="Fail a named syscall with an errno",
                summary=(
                    "Replace the return value of a named syscall with a negative "
                    "errno, so the caller observes a failure it must handle."
                ),
                category=FaultCategory.PROCESS,
                risk=RiskLevel.HIGH,
                max_safe_duration_s=120.0,
                required_caps=frozenset({Capability.SYS_ADMIN}),
                probe_caps=frozenset({"SYS_ADMIN"}),
                probe_bins=frozenset({"bpftool"}),
                tool_capabilities=frozenset({"kernel.syscall_attach"}),
                syscalls=frozenset({"read", "write", "openat", "connect", "sendmsg"}),
                mode=KernelInjectionMode.ERRNO_RETURN,
                attachment=ReverseAttachment.PROCESS,
                errno_name=ErrorCode.EIO,
                loader="ebpf-kprobe",
                reversibility_statement=ReversibilityStatement(
                    reversibility=Reversibility.REVERSIBLE,
                    undo="detach the kprobe from the matching kprobe_events entry",
                    verification=(
                        "the traced syscall returns its pre-injection value for a canary call"
                    ),
                    compensation_template="kernel.kprobe.detach",
                ),
                residue_checks=(
                    ResidueCheck(
                        facet=ResidueFacet.ATTACHMENT,
                        probe="read /sys/kernel/debug/tracing/kprobe_events",
                        expectation="no mayhem-owned kprobe entry remains for any tid",
                    ),
                    ResidueCheck(
                        facet=ResidueFacet.RETURN_VALUE,
                        probe="issue one canary call to the hooked syscall",
                        expectation="the call succeeds and returns its unhooked value",
                    ),
                ),
                missing=MissingMechanism(
                    code=MissingCode.MECHANISM_ABSENT,
                    mechanism="ebpf_kprobe_loader",
                    covers_reasons=frozenset(
                        {
                            GapReason.BIN_NOT_PROBED,
                            GapReason.CAP_BIT_UNDEFINED,
                            GapReason.TOOL_NOT_MANIFESTED,
                        }
                    ),
                    needed_by=(
                        "a provider capability under SDK 17 that loads a CO-RE eBPF "
                        "program, plus a bpftool row in _PROBE_BINS and a SYS_ADMIN "
                        "row in _CAP_BITS so the impact gate can evaluate the demand"
                    ),
                    why_no_substitute=(
                        "net.latency and fs.read_only perturb a different layer "
                        "entirely: tc acts on packets below the syscall and a "
                        "read-only mount fails at open, so neither makes a named "
                        "read() or write() return an errno mid-call"
                    ),
                    near_misses=("net.latency", "fs.read_only"),
                ),
                notes=(
                    "SYS_ADMIN is absent from _CAP_BITS today, so a descriptor "
                    "naming it is a permanent cap-bit gap until Phase 2 adds the "
                    "row; bpftool is absent from _PROBE_BINS, which is the ip-trap "
                    "shape and would gate the fault INERT forever if it were "
                    "registered without that row."
                ),
            ),
            KernelPrimitive(
                id="kernel.syscall_latency",
                family=PrimitiveFamily.KERNEL,
                title="Hold a named syscall in the kernel for a bounded window",
                summary=(
                    "Delay the return of a named syscall by a declared duration, so "
                    "the caller observes latency it cannot distinguish from load."
                ),
                category=FaultCategory.PROCESS,
                risk=RiskLevel.HIGH,
                max_safe_duration_s=60.0,
                required_caps=frozenset({Capability.SYS_ADMIN}),
                probe_caps=frozenset({"SYS_ADMIN"}),
                probe_bins=frozenset({"bpftool"}),
                tool_capabilities=frozenset({"kernel.syscall_latency"}),
                syscalls=frozenset({"read", "write", "fsync", "sendmsg"}),
                mode=KernelInjectionMode.LATENCY_DELAY,
                latency_ms=2500,
                attachment=ReverseAttachment.PROCESS,
                loader="ebpf-kprobe",
                reversibility_statement=ReversibilityStatement(
                    reversibility=Reversibility.REVERSIBLE,
                    undo="detach the delay program; in-kernel sleeps end with it",
                    verification=(
                        "a canary call to the hooked syscall completes within its pre-injection p99"
                    ),
                    compensation_template="kernel.kprobe.detach",
                ),
                residue_checks=(
                    ResidueCheck(
                        facet=ResidueFacet.ATTACHMENT,
                        probe="read /sys/kernel/debug/tracing/kprobe_events",
                        expectation="no mayhem-owned delay program remains attached",
                    ),
                ),
                incompatible_with=frozenset(
                    {"kernel.syscall_errno", "kernel.syscall_return_mutation"}
                ),
                missing=MissingMechanism(
                    code=MissingCode.MECHANISM_ABSENT,
                    mechanism="ebpf_kprobe_loader",
                    covers_reasons=frozenset(
                        {
                            GapReason.BIN_NOT_PROBED,
                            GapReason.CAP_BIT_UNDEFINED,
                            GapReason.TOOL_NOT_MANIFESTED,
                        }
                    ),
                    needed_by=(
                        "the same loader as kernel.syscall_errno, with a delay "
                        "verifier-attached program; kprobe sleep helpers are "
                        "restricted, so the window may have to be a busy-wait"
                    ),
                    why_no_substitute=(
                        "net.latency is a packet-level qdisc: it changes when bytes "
                        "arrive, not how long one syscall occupies the caller, and "
                        "a single wide write loop produces throughput loss rather "
                        "than a per-call delay"
                    ),
                    near_misses=("net.latency", "fs.write_delay"),
                ),
            ),
            KernelPrimitive(
                id="kernel.syscall_return_mutation",
                family=PrimitiveFamily.KERNEL,
                title="Rewrite a syscall's return value while letting it succeed",
                summary=(
                    "Let a named syscall complete and change the value it reports, "
                    "so the caller acts on a plausible wrong answer."
                ),
                category=FaultCategory.PROCESS,
                risk=RiskLevel.HIGH,
                max_safe_duration_s=60.0,
                required_caps=frozenset({Capability.SYS_ADMIN}),
                probe_caps=frozenset({"SYS_ADMIN"}),
                probe_bins=frozenset({"bpftool"}),
                tool_capabilities=frozenset({"kernel.syscall_attach"}),
                syscalls=frozenset({"read", "write", "getdents64"}),
                mode=KernelInjectionMode.RETURN_MUTATION,
                attachment=ReverseAttachment.PROCESS,
                return_mutation="zero",
                loader="ebpf-kprobe",
                reversibility_statement=ReversibilityStatement(
                    reversibility=Reversibility.REVERSIBLE,
                    undo="detach the program; the next call returns its real value",
                    verification=(
                        "a canary call to the hooked syscall reports the value it "
                        "reported before the injection"
                    ),
                    compensation_template="kernel.kprobe.detach",
                ),
                residue_checks=(
                    ResidueCheck(
                        facet=ResidueFacet.ATTACHMENT,
                        probe="read /sys/kernel/debug/tracing/kprobe_events",
                        expectation="no mayhem-owned rewrite program remains attached",
                    ),
                    ResidueCheck(
                        facet=ResidueFacet.RETURN_VALUE,
                        probe="canary call to the hooked syscall",
                        expectation="the reported value equals the unhooked value",
                    ),
                ),
                incompatible_with=frozenset({"kernel.syscall_errno", "kernel.syscall_latency"}),
                missing=MissingMechanism(
                    code=MissingCode.MECHANISM_ABSENT,
                    mechanism="ebpf_return_value_rewrite",
                    covers_reasons=frozenset(
                        {
                            GapReason.BIN_NOT_PROBED,
                            GapReason.CAP_BIT_UNDEFINED,
                            GapReason.TOOL_NOT_MANIFESTED,
                        }
                    ),
                    needed_by=(
                        "CO-RE programs that write the return register of a "
                        "traced syscall, which the kprobe loader alone does not "
                        "give"
                    ),
                    why_no_substitute=(
                        "http.header_inject and http.response_truncate mutate bytes "
                        "in a proxy mayhem owns; a mutated syscall return is "
                        "produced by the target's own kernel and cannot be reached "
                        "from a proxy without also rewriting everything after it"
                    ),
                    near_misses=("http.header_inject", "fs.corrupt"),
                ),
            ),
            IOPrimitive(
                id="io.capacity_exhaustion",
                family=PrimitiveFamily.IO,
                title="Consume free space in the target's own filesystem",
                summary=(
                    "Write marker files until the target filesystem's free space "
                    "crosses a declared fraction, so its writes start failing."
                ),
                category=FaultCategory.STORAGE,
                risk=RiskLevel.MEDIUM,
                maturity_floor=MaturityLevel.VERIFIED_UNIT,
                max_safe_duration_s=300.0,
                probe_bins=frozenset({"python"}),
                operation=IoOperation.WRITE,
                mode=IoMode.QUOTA,
                shim=IoShim.MARKER_FILES,
                path_param="path",
                default_path="/tmp",
                reversibility_statement=ReversibilityStatement(
                    reversibility=Reversibility.REVERSIBLE,
                    undo="unlink every marker.* sibling created by the injection",
                    verification="free space returns to within 1% of the pre-injection baseline",
                    compensation_template="storage.capacity_markers_remove",
                ),
                residue_checks=(
                    ResidueCheck(
                        facet=ResidueFacet.FILESYSTEM,
                        probe="statvfs on the target path",
                        expectation="free space within 1% of the recorded baseline",
                    ),
                    ResidueCheck(
                        facet=ResidueFacet.FILESYSTEM,
                        probe="glob marker.* in the target path",
                        expectation="no marker file remains that the injection created",
                    ),
                ),
                incompatible_with=frozenset({"io.inode_exhaustion", "io.write_delay"}),
                existing_fault_id="fs.fill",
            ),
            IOPrimitive(
                id="io.inode_exhaustion",
                family=PrimitiveFamily.IO,
                title="Consume the target filesystem's free inodes",
                summary=(
                    "Create zero-byte marker files until inode allocation fails in "
                    "the target's own filesystem, leaving capacity untouched."
                ),
                category=FaultCategory.STORAGE,
                risk=RiskLevel.MEDIUM,
                maturity_floor=MaturityLevel.VERIFIED_UNIT,
                max_safe_duration_s=300.0,
                probe_bins=frozenset({"python"}),
                operation=IoOperation.OPEN,
                mode=IoMode.QUOTA,
                shim=IoShim.MARKER_FILES,
                path_param="path",
                default_path="/tmp",
                reversibility_statement=ReversibilityStatement(
                    reversibility=Reversibility.REVERSIBLE,
                    undo="unlink every marker file created by the injection",
                    verification="free inode count returns to the pre-injection baseline",
                    compensation_template="storage.inode_markers_remove",
                ),
                residue_checks=(
                    ResidueCheck(
                        facet=ResidueFacet.INODE_TABLE,
                        probe="stat -f on the target path (f_files minus f_ffree)",
                        expectation="free inodes within 1% of the recorded baseline",
                    ),
                ),
                incompatible_with=frozenset({"io.capacity_exhaustion", "io.write_delay"}),
                existing_fault_id="fs.inode_exhaust",
            ),
            IOPrimitive(
                id="io.filesystem_read_only",
                family=PrimitiveFamily.IO,
                title="Remount a path read-only so writes fail EROFS",
                summary=(
                    "Remount the affected path read-only, so every write through it "
                    "fails with EROFS until the mount is restored."
                ),
                category=FaultCategory.STORAGE,
                risk=RiskLevel.HIGH,
                maturity_floor=MaturityLevel.VERIFIED_UNIT,
                max_safe_duration_s=120.0,
                probe_bins=frozenset({"sh"}),
                need_root=True,
                operation=IoOperation.WRITE,
                mode=IoMode.ERROR,
                shim=IoShim.REMOUNT,
                path_param="path",
                default_path="/",
                error_code=ErrorCode.EROFS,
                reversibility_statement=ReversibilityStatement(
                    reversibility=Reversibility.REVERSIBLE,
                    undo="remount the path read-write and restore its original mount options",
                    verification="a probe write to the path succeeds again",
                    compensation_template="storage.remount_readwrite",
                ),
                residue_checks=(
                    ResidueCheck(
                        facet=ResidueFacet.MOUNT,
                        probe="findmnt -no OPTIONS --target <path>",
                        expectation="the mount options match the pre-injection record",
                    ),
                ),
                existing_fault_id="fs.read_only",
                notes=(
                    "Shims the whole mount, not a selected call, so it is the "
                    "coarsest IO failure mayhem can already deliver; the near-misses "
                    "below record the ones that are not a substitute for it."
                ),
            ),
            IOPrimitive(
                id="io.read_delay",
                family=PrimitiveFamily.IO,
                title="Delay the target's reads on one mount",
                summary=(
                    "Hold reads issued against one mount for a declared window, so "
                    "the target observes read latency that is not its own load."
                ),
                category=FaultCategory.STORAGE,
                risk=RiskLevel.MEDIUM,
                max_safe_duration_s=120.0,
                required_caps=frozenset({Capability.SYS_ADMIN}),
                probe_caps=frozenset({"SYS_ADMIN"}),
                probe_bins=frozenset({"mount", "fusermount3"}),
                operation=IoOperation.READ,
                mode=IoMode.DELAY,
                delay_ms=1500,
                shim=IoShim.FUSE,
                path_param="path",
                default_path="/tmp",
                reversibility_statement=ReversibilityStatement(
                    reversibility=Reversibility.REVERSIBLE,
                    undo="unmount the shim and remount the underlying device",
                    verification="a probe read of the path completes within its baseline p99",
                    compensation_template="storage.fuse_unmount",
                ),
                residue_checks=(
                    ResidueCheck(
                        facet=ResidueFacet.MOUNT,
                        probe="findmnt --target <path>",
                        expectation="the underlying device is mounted and no fuse mount remains",
                    ),
                    ResidueCheck(
                        facet=ResidueFacet.FILESYSTEM,
                        probe="read a known file from the path and compare its digest",
                        expectation="digest matches the pre-injection record",
                    ),
                ),
                incompatible_with=frozenset(
                    {"io.write_delay", "io.read_error", "io.block_device_delay"}
                ),
                missing=MissingMechanism(
                    code=MissingCode.SUBSTRATE_UNPROVISIONED,
                    mechanism="fuse_delay_shim",
                    covers_reasons=_COVERS_BIN_AND_CAP,
                    needed_by=(
                        "a FUSE passthrough daemon, a /dev/fuce device passed into "
                        "the target container, and mount(8)/fusermount3 in the probe "
                        "set; mayhem provisions none of the three today"
                    ),
                    why_no_substitute=(
                        "fs.write_delay's mechanism is a burner process writing to "
                        "its own marker file: it adds contention on a shared "
                        "filesystem and never delays a read the target issues, so "
                        "offering it here would name a fault that does not do this"
                    ),
                    near_misses=("fs.write_delay", "fs.io_stress", "net.latency"),
                ),
            ),
            IOPrimitive(
                id="io.write_delay",
                family=PrimitiveFamily.IO,
                title="Delay the target's writes on one mount",
                summary=(
                    "Hold writes issued against one mount for a declared window, so "
                    "the target observes write latency that is not its own load."
                ),
                category=FaultCategory.STORAGE,
                risk=RiskLevel.MEDIUM,
                max_safe_duration_s=120.0,
                required_caps=frozenset({Capability.SYS_ADMIN}),
                probe_caps=frozenset({"SYS_ADMIN"}),
                probe_bins=frozenset({"mount", "fusermount3"}),
                operation=IoOperation.WRITE,
                mode=IoMode.DELAY,
                delay_ms=1500,
                shim=IoShim.FUSE,
                path_param="path",
                default_path="/tmp",
                reversibility_statement=ReversibilityStatement(
                    reversibility=Reversibility.REVERSIBLE,
                    undo="unmount the shim and remount the underlying device",
                    verification="a probe write to the path completes within its baseline p99",
                    compensation_template="storage.fuse_unmount",
                ),
                residue_checks=(
                    ResidueCheck(
                        facet=ResidueFacet.MOUNT,
                        probe="findmnt --target <path>",
                        expectation="the underlying device is mounted and no fuse mount remains",
                    ),
                    ResidueCheck(
                        facet=ResidueFacet.FILESYSTEM,
                        probe="digest a known file after a probe write",
                        expectation="the file's content is exactly what was written",
                    ),
                ),
                incompatible_with=frozenset(
                    {"io.read_delay", "io.block_device_delay", "io.capacity_exhaustion"}
                ),
                missing=MissingMechanism(
                    code=MissingCode.SUBSTRATE_UNPROVISIONED,
                    mechanism="fuse_delay_shim",
                    covers_reasons=_COVERS_BIN_AND_CAP,
                    needed_by="the same FUSE daemon and device passthrough as io.read_delay",
                    why_no_substitute=(
                        "fs.write_delay is a *contention* fault whose own name "
                        "promises a delay: the mechanism writes from a separate "
                        "process and perturbs nobody's write latency, so it is "
                        "recorded here as the near-miss it is rather than "
                        "presented as this primitive"
                    ),
                    near_misses=("fs.write_delay", "fs.io_stress"),
                ),
                notes=(
                    "The name collision with fs.write_delay is deliberate and is "
                    "the honest statement: the catalog id advertises a delay the "
                    "mechanism does not deliver. Renaming or re-scoping that id is "
                    "Phase 3 work and is not decided here."
                ),
            ),
            IOPrimitive(
                id="io.read_error",
                family=PrimitiveFamily.IO,
                title="Return EIO from the target's reads",
                summary=(
                    "Make reads against one mount return EIO, so the target "
                    "observes a media-level read failure."
                ),
                category=FaultCategory.STORAGE,
                risk=RiskLevel.HIGH,
                max_safe_duration_s=120.0,
                required_caps=frozenset({Capability.SYS_ADMIN}),
                probe_caps=frozenset({"SYS_ADMIN"}),
                probe_bins=frozenset({"dmsetup"}),
                operation=IoOperation.READ,
                mode=IoMode.ERROR,
                shim=IoShim.DEVICE_MAPPER,
                path_param="path",
                default_path="/tmp",
                error_code=ErrorCode.EIO,
                reversibility_statement=ReversibilityStatement(
                    reversibility=Reversibility.REVERSIBLE,
                    undo="tear down the error target and restore the pass-through mapping",
                    verification="a probe read of the path succeeds again",
                    compensation_template="storage.dm_error_teardown",
                ),
                residue_checks=(
                    ResidueCheck(
                        facet=ResidueFacet.MOUNT,
                        probe="dmsetup table and findmnt --target <path>",
                        expectation=(
                            "the original device backs the mount and no error target remains"
                        ),
                    ),
                ),
                incompatible_with=frozenset(
                    {"io.read_delay", "io.write_delay", "io.block_device_delay"}
                ),
                missing=MissingMechanism(
                    code=MissingCode.SUBSTRATE_UNPROVISIONED,
                    mechanism="device_mapper_error_target",
                    covers_reasons=_COVERS_BIN_AND_CAP,
                    needed_by=(
                        "/dev/mapper/control, a loop device per target, and "
                        "CAP_SYS_ADMIN in the target's capability set; mayhem "
                        "provisions no device-mapper target and the gate cannot "
                        "evaluate SYS_ADMIN today"
                    ),
                    why_no_substitute=(
                        "fs.read_only fails at open with EROFS and refuses writes as "
                        "well as reads; it cannot produce a read-only-visible EIO, "
                        "which is the failure this primitive exists to test"
                    ),
                    near_misses=("fs.read_only", "fs.corrupt"),
                    anchor_fault_id="fs.read_error",
                ),
                notes=(
                    "fs.read_error's catalog_only refusal is authoritative and this "
                    "descriptor does not weaken it: promoting it requires this "
                    "mechanism to exist, not a different one to be renamed."
                ),
            ),
            IOPrimitive(
                id="io.permission_error",
                family=PrimitiveFamily.IO,
                title="Return EACCES from the target's file operations",
                summary=(
                    "Make file operations on one path fail with permission denied, "
                    "so the target exercises its own denied-path handling."
                ),
                category=FaultCategory.STORAGE,
                risk=RiskLevel.HIGH,
                max_safe_duration_s=120.0,
                required_caps=frozenset({Capability.FS_CONTROL, Capability.SYS_ADMIN}),
                probe_caps=frozenset({"SYS_ADMIN"}),
                probe_bins=frozenset({"fusermount3"}),
                tool_capabilities=frozenset({"storage.fuse_shim"}),
                operation=IoOperation.OPEN,
                mode=IoMode.ERROR,
                shim=IoShim.FUSE,
                path_param="path",
                default_path="/tmp",
                error_code=ErrorCode.EACCES,
                reversibility_statement=ReversibilityStatement(
                    reversibility=Reversibility.REVERSIBLE,
                    undo="unmount the shim; the underlying path keeps its original owner and mode",
                    verification="the target's own uid can open the path again",
                    compensation_template="storage.fuse_unmount",
                ),
                residue_checks=(
                    ResidueCheck(
                        facet=ResidueFacet.MOUNT,
                        probe="stat -c '%U %a' <path> and findmnt --target <path>",
                        expectation="owner and mode match the pre-injection record",
                    ),
                ),
                missing=MissingMechanism(
                    code=MissingCode.MECHANISM_ABSENT,
                    mechanism="permission_preserving_executor",
                    covers_reasons=frozenset(
                        {
                            GapReason.BIN_NOT_PROBED,
                            GapReason.CAP_BIT_UNDEFINED,
                            GapReason.TOOL_NOT_MANIFESTED,
                        }
                    ),
                    needed_by=(
                        "a mechanism that answers with EACCES without changing the "
                        "path's owner or mode, so the undo is a remount rather than "
                        "a chown that itself perturbs the target"
                    ),
                    why_no_substitute=(
                        "chmod 0000 restores the recorded mode afterwards, but it "
                        "changes what the target can see about the path in the "
                        "window and cannot express a per-call denial; the catalog "
                        "refuses fs.permission_failure for exactly this reason"
                    ),
                    near_misses=("fs.read_only", "process.thread_exhaust"),
                    anchor_fault_id="fs.permission_failure",
                ),
            ),
            IOPrimitive(
                id="io.block_device_delay",
                family=PrimitiveFamily.IO,
                title="Delay IO on a block device, not on one path",
                summary=(
                    "Insert a delay target below the filesystem, so every IO on the "
                    "device is affected regardless of which path asked for it."
                ),
                category=FaultCategory.STORAGE,
                risk=RiskLevel.HIGH,
                max_safe_duration_s=120.0,
                required_caps=frozenset({Capability.SYS_ADMIN}),
                probe_caps=frozenset({"SYS_ADMIN"}),
                probe_bins=frozenset({"dmsetup"}),
                operation=IoOperation.META,
                mode=IoMode.DELAY,
                delay_ms=2000,
                shim=IoShim.DEVICE_MAPPER,
                path_param="device",
                default_path="/dev/<device>",
                reversibility_statement=ReversibilityStatement(
                    reversibility=Reversibility.REVERSIBLE,
                    undo="remove the delay target and reactivate the original device",
                    verification="a probe IO on the device completes within its baseline p99",
                    compensation_template="storage.dm_delay_teardown",
                ),
                residue_checks=(
                    ResidueCheck(
                        facet=ResidueFacet.MOUNT,
                        probe="dmsetup table plus lsblk --output NAME,HOLD,TYPE",
                        expectation="no mayhem-created mapping remains and no device is held",
                    ),
                ),
                incompatible_with=frozenset({"io.read_delay", "io.write_delay", "io.read_error"}),
                missing=MissingMechanism(
                    code=MissingCode.SUBSTRATE_UNPROVISIONED,
                    mechanism="device_mapper_delay_target",
                    covers_reasons=_COVERS_BIN_AND_CAP,
                    needed_by=(
                        "the same loop-device and dmsetup provisioning as "
                        "io.read_error; the target is the whole device, so it also "
                        "needs a read-only snapshot of the device to reactivate"
                    ),
                    why_no_substitute=(
                        "fs.io_stress drives throughput from a burner process and "
                        "changes how much load the device sees, not how long a "
                        "target's own IO waits; netem delays packets and never "
                        "reaches a block queue"
                    ),
                    near_misses=("fs.io_stress", "net.latency", "cpu.throttle"),
                ),
            ),
            IOPrimitive(
                id="io.torn_write",
                family=PrimitiveFamily.IO,
                title="Land a partial write and report success",
                summary=(
                    "Let a write reach the device truncated while the syscall "
                    "reports the full count, so the target holds corrupt data."
                ),
                category=FaultCategory.STORAGE,
                risk=RiskLevel.CRITICAL,
                max_safe_duration_s=60.0,
                required_caps=frozenset({Capability.SYS_ADMIN}),
                probe_caps=frozenset({"SYS_ADMIN"}),
                probe_bins=frozenset({"dmsetup"}),
                operation=IoOperation.WRITE,
                mode=IoMode.CORRUPT,
                shim=IoShim.DEVICE_MAPPER,
                path_param="path",
                default_path="/tmp",
                reversibility_statement=ReversibilityStatement(
                    reversibility=Reversibility.IRREVERSIBLE,
                    undo="none: bytes already accepted by the target cannot be recalled",
                    verification=(
                        "record the affected file's pre-injection digest; a mismatch "
                        "after the window is the expected outcome, not a defect"
                    ),
                    reconciliation=(
                        "restore the file from the pre-injection digest taken at "
                        "attach time, or accept the corruption and mark the target "
                        "dirty; mayhem does not choose for the operator"
                    ),
                ),
                residue_checks=(
                    ResidueCheck(
                        facet=ResidueFacet.FILESYSTEM,
                        probe="digest the target file and compare with the pre-injection record",
                        expectation=(
                            "the digest differs and the divergence is reported as "
                            "unrecoverable, not as a clean undo"
                        ),
                    ),
                ),
                missing=MissingMechanism(
                    code=MissingCode.SUBSTRATE_UNPROVISIONED,
                    mechanism="device_mapper_partial_write_target",
                    covers_reasons=_COVERS_BIN_AND_CAP,
                    needed_by=(
                        "a target that truncates a bio while reporting completion, "
                        "plus a pre-write snapshot the undo could otherwise restore "
                        "from — which is why this primitive is declared irreversible "
                        "rather than reversible with a best-effort undo"
                    ),
                    why_no_substitute=(
                        "fs.corrupt rewrites file contents after the fact and has a "
                        "real undo because it copies the original aside; a write "
                        "that is truncated in flight never had an original on disk "
                        "for the target to give back"
                    ),
                    near_misses=("fs.corrupt", "fs.read_error"),
                ),
            ),
            JVMPrimitive(
                id="jvm.method_delay",
                family=PrimitiveFamily.JVM,
                title="Hold a Java method's return for a bounded window",
                summary=(
                    "Instrument one method in the target VM so its return is held, "
                    "and the caller observes latency inside the process."
                ),
                category=FaultCategory.PROCESS,
                risk=RiskLevel.MEDIUM,
                max_safe_duration_s=120.0,
                required_caps=frozenset({Capability.PROCESS_CONTROL}),
                probe_bins=frozenset({"jcmd"}),
                tool_capabilities=frozenset({"jvm.attach"}),
                target_class="java.util.concurrent.ThreadPoolExecutor",
                target_method="getActiveCount",
                instrumentation=JVMInstrumentation.JVMTI_AGENT,
                mode=JvmInjectionMode.METHOD_DELAY,
                delay_ms=1200,
                reversibility_statement=ReversibilityStatement(
                    reversibility=Reversibility.REVERSIBLE,
                    undo="detach the agent and restore the original bytecode",
                    verification=(
                        "the instrumented method's own latency returns to its pre-injection p99"
                    ),
                    compensation_template="jvm.agent_detach",
                ),
                residue_checks=(
                    ResidueCheck(
                        facet=ResidueFacet.BYTECODE,
                        probe="re-dump the method with the agent's own writer disabled",
                        expectation=(
                            "the dumped bytecode is byte-identical to the pre-injection dump"
                        ),
                    ),
                    ResidueCheck(
                        facet=ResidueFacet.PROCESS_STATE,
                        probe="jcmd <pid> VM.class_hierarchy / thread dump",
                        expectation="no mayhem agent thread remains in the target VM",
                    ),
                ),
                missing=MissingMechanism(
                    code=MissingCode.MECHANISM_ABSENT,
                    mechanism="jvm_attach_agent",
                    covers_reasons=_COVERS_BIN_AND_TOOL,
                    needed_by=(
                        "a JVMTI agent loader (attach API or jattach), a target VM "
                        "that permits attach, and a container image with a JVM; mayhem "
                        "ships no JVM support of any kind, so the gate has no bin to "
                        "probe and no manifest to declare one"
                    ),
                    why_no_substitute=(
                        "app.response_5xx and http.latency perturb a proxy mayhem "
                        "owns; the method-level timing this primitive is about lives "
                        "inside the target's own VM and is invisible to a proxy"
                    ),
                    near_misses=("app.response_5xx", "http.latency", "proc.pause"),
                ),
            ),
            JVMPrimitive(
                id="jvm.return_value_mutation",
                family=PrimitiveFamily.JVM,
                title="Replace a Java method's return value in the target VM",
                summary=(
                    "Instrument one method so it returns a different value, and the "
                    "caller acts on a plausible wrong answer."
                ),
                category=FaultCategory.PROCESS,
                risk=RiskLevel.HIGH,
                max_safe_duration_s=120.0,
                required_caps=frozenset({Capability.PROCESS_CONTROL}),
                probe_bins=frozenset({"jcmd"}),
                tool_capabilities=frozenset({"jvm.attach"}),
                target_class="java.util.concurrent.ThreadPoolExecutor",
                target_method="getActiveCount",
                instrumentation=JVMInstrumentation.JAVA_INSTRUMENTATION,
                mode=JvmInjectionMode.RETURN_MUTATION,
                reversibility_statement=ReversibilityStatement(
                    reversibility=Reversibility.REVERSIBLE,
                    undo="detach the agent and restore the original bytecode",
                    verification="the method returns its pre-injection value for a canary call",
                    compensation_template="jvm.agent_detach",
                ),
                residue_checks=(
                    ResidueCheck(
                        facet=ResidueFacet.BYTECODE,
                        probe="re-dump the instrumented method with the agent removed",
                        expectation="the dump is byte-identical to the pre-injection dump",
                    ),
                ),
                missing=MissingMechanism(
                    code=MissingCode.MECHANISM_ABSENT,
                    mechanism="jvm_bytecode_instrumentation",
                    covers_reasons=_COVERS_BIN_AND_TOOL,
                    needed_by=(
                        "a java.lang.instrument transformer running inside the target "
                        "VM, which presupposes the attach loader in jvm.method_delay"
                    ),
                    why_no_substitute=(
                        "fuzz.protocol_abuse mutates requests arriving at a socket; "
                        "the value this primitive corrupts is computed inside the "
                        "target and never crosses a boundary mayhem could rewrite"
                    ),
                    near_misses=("fuzz.protocol_abuse", "http.header_inject"),
                ),
            ),
            JVMPrimitive(
                id="jvm.exception_injection",
                family=PrimitiveFamily.JVM,
                title="Throw from a Java method in the target VM",
                summary=(
                    "Instrument one method to throw a named exception before it "
                    "returns, so the target's own recovery path runs."
                ),
                category=FaultCategory.PROCESS,
                risk=RiskLevel.HIGH,
                max_safe_duration_s=120.0,
                required_caps=frozenset({Capability.PROCESS_CONTROL}),
                probe_bins=frozenset({"jcmd"}),
                tool_capabilities=frozenset({"jvm.attach"}),
                target_class="java.util.concurrent.ThreadPoolExecutor",
                target_method="execute",
                instrumentation=JVMInstrumentation.JVMTI_AGENT,
                mode=JvmInjectionMode.EXCEPTION_INJECT,
                exception_class="java.util.concurrent.RejectedExecutionException",
                reversibility_statement=ReversibilityStatement(
                    reversibility=Reversibility.REVERSIBLE,
                    undo="detach the agent and restore the original bytecode",
                    verification="the method completes normally for a canary call",
                    compensation_template="jvm.agent_detach",
                ),
                residue_checks=(
                    ResidueCheck(
                        facet=ResidueFacet.BYTECODE,
                        probe="re-dump the instrumented method with the agent removed",
                        expectation="the dump is byte-identical to the pre-injection dump",
                    ),
                ),
                missing=MissingMechanism(
                    code=MissingCode.MECHANISM_ABSENT,
                    mechanism="jvm_attach_agent",
                    covers_reasons=_COVERS_BIN_AND_TOOL,
                    needed_by=(
                        "the attach loader, plus a throw site inside the target's own bytecode"
                    ),
                    why_no_substitute=(
                        "app.response_5xx returns a status from a proxy mayhem owns; "
                        "an exception raised inside the method unwinds a stack the "
                        "target owns, which a proxy cannot produce"
                    ),
                    near_misses=("app.response_5xx", "db.query_error"),
                    anchor_fault_id="app.exception",
                ),
            ),
            JVMPrimitive(
                id="jvm.allocation_pressure",
                family=PrimitiveFamily.JVM,
                title="Allocate in the target JVM's own heap",
                summary=(
                    "Retain allocations in the target's heap until its collector "
                    "runs under pressure, rather than in a process beside it."
                ),
                category=FaultCategory.PROCESS,
                risk=RiskLevel.HIGH,
                max_safe_duration_s=120.0,
                required_caps=frozenset({Capability.PROCESS_CONTROL}),
                probe_bins=frozenset({"jcmd"}),
                tool_capabilities=frozenset({"jvm.attach"}),
                target_class="java.lang.System",
                target_method="gc",
                instrumentation=JVMInstrumentation.JVMTI_AGENT,
                mode=JvmInjectionMode.ALLOCATION_PRESSURE,
                pressure_units=262_144,
                reversibility_statement=ReversibilityStatement(
                    reversibility=Reversibility.REVERSIBLE,
                    undo="drop the agent's retained references and let the heap fall",
                    verification="the target's committed heap returns to within 10% of baseline",
                    compensation_template="jvm.agent_detach",
                ),
                residue_checks=(
                    ResidueCheck(
                        facet=ResidueFacet.HEAP,
                        probe="jcmd <pid> GC.heap_info",
                        expectation="used heap within 10% of the pre-injection baseline",
                    ),
                    ResidueCheck(
                        facet=ResidueFacet.THREAD_POOL,
                        probe="jcmd <pid> Thread.print",
                        expectation="no mayhem allocation thread remains in the target VM",
                    ),
                ),
                missing=MissingMechanism(
                    code=MissingCode.MECHANISM_ABSENT,
                    mechanism="jvm_attach_agent",
                    covers_reasons=_COVERS_BIN_AND_TOOL,
                    needed_by=(
                        "code executing *inside* the target's heap; mem.exhaust "
                        "allocates from a burner process, which is a different heap"
                    ),
                    why_no_substitute=(
                        "mem.exhaust commits memory in a process mayhem starts, so the "
                        "target's own collector never runs and its heap never grows; "
                        "the two faults exercise different collectors and different "
                        "failure handling"
                    ),
                    near_misses=("mem.exhaust", "mem.swap_pressure"),
                ),
            ),
            JVMPrimitive(
                id="jvm.gc_pressure",
                family=PrimitiveFamily.JVM,
                title="Drive the target JVM's collector without holding a payload",
                summary=(
                    "Nudge the target's GC so allocation and collection dominate its "
                    "CPU, leaving the heap's high-water mark unchanged."
                ),
                category=FaultCategory.PROCESS,
                risk=RiskLevel.MEDIUM,
                max_safe_duration_s=120.0,
                required_caps=frozenset({Capability.PROCESS_CONTROL}),
                probe_bins=frozenset({"jcmd"}),
                tool_capabilities=frozenset({"jvm.attach"}),
                target_class="java.lang.System",
                target_method="gc",
                instrumentation=JVMInstrumentation.JVMTI_AGENT,
                mode=JvmInjectionMode.GC_PRESSURE,
                pressure_units=500,
                reversibility_statement=ReversibilityStatement(
                    reversibility=Reversibility.REVERSIBLE,
                    undo="stop requesting collections; the target's own GC resumes",
                    verification="GC CPU share returns to within 10% of baseline",
                    compensation_template="jvm.agent_detach",
                ),
                residue_checks=(
                    ResidueCheck(
                        facet=ResidueFacet.HEAP,
                        probe="jstat -gc <pid> over the window",
                        expectation="collection count returns to the pre-injection rate",
                    ),
                ),
                missing=MissingMechanism(
                    code=MissingCode.MECHANISM_ABSENT,
                    mechanism="jvm_attach_agent",
                    covers_reasons=_COVERS_BIN_AND_TOOL,
                    needed_by=(
                        "an agent inside the target VM that can request collections "
                        "and observe the collector's own accounting"
                    ),
                    why_no_substitute=(
                        "cpu.saturate burns CPU with a hashing loop in a burner "
                        "process: the target's collector is untouched and its GC CPU "
                        "share stays flat, so the observation this primitive is about "
                        "never happens"
                    ),
                    near_misses=("cpu.saturate", "load.spike"),
                ),
            ),
            JVMPrimitive(
                id="jvm.thread_pressure",
                family=PrimitiveFamily.JVM,
                title="Occupy the target JVM's worker pool",
                summary=(
                    "Hold the target's executor threads so queued work stops being "
                    "picked up, without touching the OS thread limit."
                ),
                category=FaultCategory.PROCESS,
                risk=RiskLevel.HIGH,
                max_safe_duration_s=120.0,
                required_caps=frozenset({Capability.PROCESS_CONTROL}),
                probe_bins=frozenset({"jcmd"}),
                tool_capabilities=frozenset({"jvm.attach"}),
                target_class="java.util.concurrent.ThreadPoolExecutor",
                target_method="getActiveCount",
                instrumentation=JVMInstrumentation.JAVA_INSTRUMENTATION,
                mode=JvmInjectionMode.THREAD_PRESSURE,
                pressure_units=64,
                reversibility_statement=ReversibilityStatement(
                    reversibility=Reversibility.REVERSIBLE,
                    undo="detach the agent; the pool's threads return to it",
                    verification="the pool's active count returns to its pre-injection value",
                    compensation_template="jvm.agent_detach",
                ),
                residue_checks=(
                    ResidueCheck(
                        facet=ResidueFacet.THREAD_POOL,
                        probe="jcmd <pid> Thread.print filtered to the pool's threads",
                        expectation=(
                            "no mayhem-owned worker remains and pool size is back to baseline"
                        ),
                    ),
                ),
                incompatible_with=frozenset({"jvm.method_delay"}),
                missing=MissingMechanism(
                    code=MissingCode.MECHANISM_ABSENT,
                    mechanism="jvm_attach_agent",
                    covers_reasons=_COVERS_BIN_AND_TOOL,
                    needed_by=(
                        "an agent that submits and holds work on the target's own "
                        "executor, which requires the in-VM instrumentation above"
                    ),
                    why_no_substitute=(
                        "process.thread_exhaust raises the process's thread count "
                        "toward its rlimit: it is an OS-level exhaustion with a "
                        "different symptom, a different recovery, and a different "
                        "undo, and the target's pool can be healthy while the "
                        "process is out of threads"
                    ),
                    near_misses=("process.thread_exhaust", "proc.pause"),
                ),
            ),
            ClockPrimitive(
                id="clock.realtime_offset",
                family=PrimitiveFamily.CLOCK,
                title="Shift CLOCK_REALTIME by a signed offset",
                summary=(
                    "Step the wall clock by a declared offset and restore it on the "
                    "undo, so certificate and token validity logic is exercised."
                ),
                category=FaultCategory.CLOCK,
                risk=RiskLevel.HIGH,
                maturity_floor=MaturityLevel.VERIFIED_UNIT,
                max_safe_duration_s=300.0,
                required_caps=frozenset({Capability.NET_ADMIN}),
                probe_caps=frozenset({"SYS_TIME"}),
                probe_bins=frozenset({"date"}),
                clock_id=ClockId.REALTIME,
                mode=ClockMode.OFFSET,
                offset_ms=60_000,
                reversibility_statement=ReversibilityStatement(
                    reversibility=Reversibility.REVERSIBLE,
                    undo="step CLOCK_REALTIME back by the applied offset",
                    verification="date reads within 1s of the pre-injection wall clock",
                    compensation_template="clock.realtime_restore",
                ),
                residue_checks=(
                    ResidueCheck(
                        facet=ResidueFacet.CLOCK,
                        probe="date +%s%3N compared with the drill host's clock",
                        expectation="the target's offset is within 1s of the recorded baseline",
                    ),
                ),
                existing_fault_id="clock.skew",
                notes=(
                    "SYS_TIME maps to Capability.NET_ADMIN because that is what "
                    "clock.skew declares today; the mapping is restated in "
                    "_AGENT_CAP_BY_CAP_BIT rather than inventing a ninth Capability."
                ),
            ),
            ClockPrimitive(
                id="clock.realtime_freeze",
                family=PrimitiveFamily.CLOCK,
                title="Stop CLOCK_REALTIME advancing for the target",
                summary=(
                    "Freeze the target's wall clock for a window, so time-based logic "
                    "inside it observes a stopped time."
                ),
                category=FaultCategory.CLOCK,
                risk=RiskLevel.HIGH,
                max_safe_duration_s=120.0,
                required_caps=frozenset({Capability.NET_ADMIN}),
                probe_caps=frozenset({"SYS_TIME"}),
                probe_bins=frozenset({"date", "faketime"}),
                tool_capabilities=frozenset({"clock.intercept"}),
                clock_id=ClockId.REALTIME,
                mode=ClockMode.FREEZE,
                scoped_to_process=True,
                reversibility_statement=ReversibilityStatement(
                    reversibility=Reversibility.REVERSIBLE,
                    undo="remove the interception and restore the library's real clock reads",
                    verification="two successive date reads in the target differ by at least 1s",
                    compensation_template="clock.interception_remove",
                ),
                residue_checks=(
                    ResidueCheck(
                        facet=ResidueFacet.CLOCK,
                        probe="two successive date reads inside the target, 5s apart in wall time",
                        expectation="the reads differ, so the clock is advancing again",
                    ),
                    ResidueCheck(
                        facet=ResidueFacet.PROCESS_STATE,
                        probe="ldd /proc/<pid>/maps of the target",
                        expectation=(
                            "no interception library is mapped into the target's address space"
                        ),
                    ),
                ),
                incompatible_with=frozenset({"clock.realtime_offset"}),
                missing=MissingMechanism(
                    code=MissingCode.MECHANISM_ABSENT,
                    mechanism="clock_interception_preload",
                    covers_reasons=_COVERS_BIN_AND_TOOL,
                    needed_by=(
                        "a libfaketime-class preload into the target process, with an "
                        "undo that removes the mapping; mayhem cannot inject a library "
                        "into a running process and has no preload lane"
                    ),
                    why_no_substitute=(
                        "clock.skew sets an offset and the clock keeps running, so it "
                        "never exercises a deadline that fails because time stood "
                        "still; container.pause stops execution entirely, so the "
                        "target observes neither an advancing nor a frozen clock"
                    ),
                    near_misses=("clock.skew", "container.pause"),
                    anchor_fault_id="clock.freeze",
                ),
            ),
            ClockPrimitive(
                id="clock.monotonic_offset",
                family=PrimitiveFamily.CLOCK,
                title="Shift CLOCK_MONOTONIC by a declared offset",
                summary=(
                    "Offset the monotonic clock the target measures elapsed time "
                    "with, so its timeout arithmetic is wrong."
                ),
                category=FaultCategory.CLOCK,
                risk=RiskLevel.HIGH,
                max_safe_duration_s=120.0,
                required_caps=frozenset({Capability.NET_ADMIN}),
                probe_caps=frozenset({"SYS_TIME"}),
                tool_capabilities=frozenset({"clock.intercept"}),
                clock_id=ClockId.MONOTONIC,
                mode=ClockMode.OFFSET,
                offset_ms=5_000,
                scoped_to_process=True,
                reversibility_statement=ReversibilityStatement(
                    reversibility=Reversibility.REVERSIBLE,
                    undo="remove the interception and restore the process's real monotonic reads",
                    verification="the target's elapsed-time reads match the host's within 100ms",
                    compensation_template="clock.interception_remove",
                ),
                residue_checks=(
                    ResidueCheck(
                        facet=ResidueFacet.CLOCK,
                        probe=(
                            "read the monotonic clock in the target and on the "
                            "host over the same window"
                        ),
                        expectation="the two agree within 100ms, so no offset is left behind",
                    ),
                ),
                incompatible_with=frozenset({"clock.monotonic_freeze"}),
                missing=MissingMechanism(
                    code=MissingCode.NOT_STEPPABLE,
                    mechanism="monotonic_offset_is_unachievable_on_linux",
                    covers_reasons=_COVERS_TOOL_ONLY,
                    needed_by=(
                        "nothing on Linux. CLOCK_MONOTONIC is not steppable: "
                        "adjtimex steps CLOCK_REALTIME only, and the monotonic clock "
                        "can merely be slewed within a few hundred ppm, so a 5s "
                        "offset is not reachable by any host facility"
                    ),
                    why_no_substitute=(
                        "clock.skew moves CLOCK_REALTIME, which is a different clock "
                        "read by different code; a target using "
                        "System.nanoTime() is untouched by it, so presenting the "
                        "offset as coverage for monotonic logic would be false"
                    ),
                    near_misses=("clock.skew",),
                    unachievable_substrate=True,
                ),
                notes=(
                    "The declared offset_ms is the offset a *test* would need, kept "
                    "so the impossibility is stated against a concrete demand rather "
                    " than in the abstract. It is not a default the mechanism could "
                    "honour."
                ),
            ),
            ClockPrimitive(
                id="clock.monotonic_freeze",
                family=PrimitiveFamily.CLOCK,
                title="Stop CLOCK_MONOTONIC advancing for the target",
                summary=(
                    "Freeze the monotonic clock the target times deadlines with, so "
                    "its timeouts never fire."
                ),
                category=FaultCategory.CLOCK,
                risk=RiskLevel.HIGH,
                max_safe_duration_s=120.0,
                required_caps=frozenset({Capability.NET_ADMIN}),
                probe_caps=frozenset({"SYS_TIME"}),
                tool_capabilities=frozenset({"clock.intercept"}),
                clock_id=ClockId.MONOTONIC,
                mode=ClockMode.FREEZE,
                scoped_to_process=True,
                reversibility_statement=ReversibilityStatement(
                    reversibility=Reversibility.REVERSIBLE,
                    undo="remove the interception and restore the process's real monotonic reads",
                    verification="the target's monotonic clock advances across a 5s wall window",
                    compensation_template="clock.interception_remove",
                ),
                residue_checks=(
                    ResidueCheck(
                        facet=ResidueFacet.CLOCK,
                        probe="two monotonic reads in the target, 5s apart in wall time",
                        expectation="the monotonic delta is at least 4.5s, so the clock runs again",
                    ),
                ),
                incompatible_with=frozenset({"clock.monotonic_offset"}),
                missing=MissingMechanism(
                    code=MissingCode.NOT_STEPPABLE,
                    mechanism="monotonic_freeze_is_unachievable_on_linux",
                    covers_reasons=_COVERS_TOOL_ONLY,
                    needed_by=(
                        "nothing at host level. Freezing CLOCK_MONOTONIC would mean "
                        "stopping the timekeeping interrupt path, which is not a "
                        "tunable and would freeze every process on the host"
                    ),
                    why_no_substitute=(
                        "container.pause suspends the target's threads, so nothing in "
                        "it measures elapsed time; it demonstrates nothing about a "
                        "deadline that fails to fire while the process is running"
                    ),
                    near_misses=("container.pause", "proc.pause"),
                    unachievable_substrate=True,
                ),
            ),
        )
    }
)


# ── the parameter grammar, and what a request would attach ───────────────────


class ParamKind(StrEnum):
    """How one parameter's value is constrained.

    The vocabulary is closed because a parameter whose constraints live only in a
    mechanism's prose is a parameter nobody can validate: the grammar below is what
    a *decision* can check, and a decision that cannot check a value has to trust
    the thing it is deciding about.

    Attributes:
        ENUM: One of :attr:`PrimitiveParam.choices`. The default shape.
        INTEGER: A bounded integer, in :attr:`PrimitiveParam.unit`.
        PATH: An absolute POSIX path, because a relative one resolves against
            whatever working directory the injector happens to run with — which is
            not a target the operator chose.
        IDENTIFIER: A dotted or underscored name (a syscall, a Java class).
    """

    ENUM = "enum"
    INTEGER = "integer"
    PATH = "path"
    IDENTIFIER = "identifier"


class PrimitiveParam(BaseModel):
    """One parameter a primitive's request may carry, and what makes it legal.

    Attributes:
        name: The parameter name, ``Identifier``-shaped.
        kind: Which constraint applies.
        unit: Human name for the value's unit (``ms``, ``ppm``, ``""``).
        required: True when a request must carry it. Derived, not editorial: a
            parameter the descriptor already fixes a default for is optional, and
            one it cannot default (a magnitude, a target) is required.
        default: The descriptor's own value, when it has one.
        choices: The closed vocabulary, non-empty iff ``kind`` is ``ENUM``.
        minimum: Inclusive lower bound for an ``INTEGER``.
        maximum: Inclusive upper bound for an ``INTEGER``.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    name: Identifier
    kind: ParamKind
    unit: str = ""
    required: bool = False
    default: str | int | None = None
    choices: tuple[str, ...] = ()
    minimum: int | None = None
    maximum: int | None = None

    @model_validator(mode="after")
    def _param_is_well_formed(self) -> PrimitiveParam:
        if self.kind is ParamKind.ENUM and not self.choices:
            raise ValueError(f"enum parameter {self.name!r} offers no choices")
        if self.kind is ParamKind.INTEGER and (self.minimum is None or self.maximum is None):
            raise ValueError(
                f"integer parameter {self.name!r} must declare both bounds: an unbounded "
                "magnitude is not a decision"
            )
        if self.kind is not ParamKind.INTEGER and (self.minimum is not None or self.maximum):
            raise ValueError(f"parameter {self.name!r} is not an integer and declares no bounds")
        if self.minimum is not None and self.maximum is not None and self.minimum > self.maximum:
            raise ValueError(f"parameter {self.name!r} has an empty range")
        if self.default is not None and not self._within(str(self.default)):
            raise ValueError(f"parameter {self.name!r} default {self.default!r} is out of range")
        if not self.unit.strip() and self.kind is ParamKind.INTEGER:
            raise ValueError(f"integer parameter {self.name!r} must name its unit")
        return self

    def _within(self, value: str) -> bool:
        if self.kind is ParamKind.ENUM:
            return value in self.choices
        if self.kind is not ParamKind.INTEGER:
            return True
        try:
            number = int(value)
        except ValueError:
            return False
        assert self.minimum is not None and self.maximum is not None
        return self.minimum <= number <= self.maximum

    def describe(self) -> str:
        """The constraint, without repeating the name — a renderer supplies that.

        Keeping the name out is what makes a grammar renderable as a list rather
        than as a sentence per entry, and it is why ``describe`` reads the same
        in a refusal message and in a table.
        """
        if self.kind is ParamKind.ENUM:
            return "one of " + ", ".join(self.choices)
        if self.kind is ParamKind.INTEGER:
            return f"{self.minimum}..{self.maximum} {self.unit}".strip()
        if self.kind is ParamKind.PATH:
            return "an absolute POSIX path"
        return "a dotted or underscored identifier"


class AttachSpecification(BaseModel):
    """What a request would attach — the *decision*, never the operation.

    This is the whole of plan 04's mechanism contract on the domain side: a
    description a mechanism would have to satisfy. Nothing here loads a program,
    opens a device, or attaches an agent, and the field is called a specification
    rather than a plan because a plan is something that gets executed.

    It exists for two reasons that are the same reason:

    * it is what the Phase-5 inertness guard compares. Two distinct parameter
      values must produce two distinct specifications, because a specification
      that ignores a parameter is the shape every inert parameter has;
    * it is the value a refused request carries *instead of* a weaker mechanism.
      There is no ``substituted_with`` field, for the reason
      :class:`MissingMechanism` has no ``substitute`` field.

    Attributes:
        primitive_id: Which descriptor this is for.
        family: The plan-04 family, carried so a mechanism loader can dispatch on
            one field rather than re-deriving it from the id's prefix.
        mode: The descriptor's mode, as the primitive's own enum value.
        mechanism: The mechanism that would have to exist — named whether it does
            or not, so the specification reads the same for an injectable primitive
            and a blocked one.
        targets: The target selector values, in a stable order.
        magnitude: The magnitude's value, when the mode has one.
        unit: The magnitude's unit, so ``2500`` is not read as 2500 bytes.
        undo: The descriptor's undo statement, verbatim. A specification that
            could not say how it comes back would not be safe to hand to anyone.
        residue_probes: The descriptor's residue probes, verbatim.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    primitive_id: str
    family: str
    mode: str
    mechanism: str
    targets: tuple[tuple[str, str], ...]
    magnitude: int | None = None
    unit: str = ""
    undo: str = Field(min_length=1)
    residue_probes: tuple[str, ...] = Field(min_length=1)

    def fingerprint(self) -> str:
        """A stable one-line rendering, for comparing two requests for equality.

        Two requests with the same fingerprint are the same attachment. Written as
        a join over every field rather than as a hash so that a difference is
        *readable* in a failing assertion — a digest that differs tells you
        nothing about which parameter moved.
        """
        targets = ",".join(f"{key}={value}" for key, value in self.targets)
        magnitude = "-" if self.magnitude is None else f"{self.magnitude} {self.unit}"
        return (
            f"{self.primitive_id}|{self.family}|{self.mode}|{self.mechanism}"
            f"|targets={targets}|magnitude={magnitude}"
        )


#: The modes whose *effect scales with an amount*, and therefore must carry one.
#:
#: Derived once here and enforced twice: by each family's own validator (which
#: refuses a descriptor that omits the magnitude) and by :func:`parameter_grammar`
#: (which refuses to describe one). A mode absent from this set — ``FREEZE``,
#: ``QUOTA``, ``CORRUPT`` — either has no amount to scale by or carries its
#: magnitude in the backing catalog entry's own parameters, which
#: :func:`magnitude_holder` reports rather than restates.
SCALING_KERNEL_MODES: Final[frozenset[KernelInjectionMode]] = frozenset(
    {KernelInjectionMode.LATENCY_DELAY}
)
SCALING_IO_MODES: Final[frozenset[IoMode]] = frozenset({IoMode.DELAY})
SCALING_JVM_MODES: Final[frozenset[JvmInjectionMode]] = frozenset(
    {
        JvmInjectionMode.METHOD_DELAY,
        JvmInjectionMode.ALLOCATION_PRESSURE,
        JvmInjectionMode.GC_PRESSURE,
        JvmInjectionMode.THREAD_PRESSURE,
    }
)
SCALING_CLOCK_MODES: Final[frozenset[ClockMode]] = frozenset({ClockMode.RATE})


def _ms_param(name: str, default: int | None, ceiling_ms: float) -> PrimitiveParam:
    """A duration-magnitude parameter, bounded by the descriptor's own window.

    One constructor so the bound is the same expression in every grammar: a
    magnitude may not outlast ``max_safe_duration_s``, because a fault that
    outlives its own recovery window cannot be undone in the time the plan allows
    for undoing it.
    """
    return PrimitiveParam(
        name=name,
        kind=ParamKind.INTEGER,
        unit="ms",
        required=True,
        default=default,
        minimum=MIN_MAGNITUDE,
        maximum=int(ceiling_ms),
    )


def _enum_param(
    name: str, choices: Iterable[str], *, default: str | None = None, required: bool = False
) -> PrimitiveParam:
    """A closed-vocabulary parameter, sorted so the grammar is byte-stable."""
    ordered = tuple(sorted(choices))
    return PrimitiveParam(
        name=name,
        kind=ParamKind.ENUM,
        required=required,
        default=default,
        choices=ordered,
    )


def parameter_grammar(primitive: LowLevelPrimitive) -> tuple[PrimitiveParam, ...]:
    """Every parameter *primitive*'s request may carry, derived from the descriptor.

    **Derived, never hand-written.** Phase 1 recorded "descriptors carry no
    ``params_schema``" as a limitation and named this as Phase 3's job; deriving
    the grammar from fields the descriptor already *validates* is what makes that
    job finishable without a second source of truth. A hand-written grammar would
    be free to disagree with the model — the same class of drift that makes an
    impact-gate ``REQUIREMENTS`` row name a binary no fault probes.

    Each family contributes its target selectors and then, exactly when the mode
    calls for it, its magnitude:

    * ``kernel``: the syscalls it declares (the closed set *is* the vocabulary,
      so a typo is a refused request rather than a kprobe that never fires), the
      attach scope, and — for ``ERRNO_RETURN`` the errno, for ``LATENCY_DELAY``
      the latency, for ``RETURN_MUTATION`` the mutation — a value from the same
      closed tables the descriptor was validated against;
    * ``io``: its ``path_param`` under its own name (so ``device`` for the
      device-mapper target and ``path`` for a mount), the operation, and the
      delay for ``DELAY``;
    * ``jvm``: the target class and method, the instrumentation channel, and the
      mode's own quantity;
    * ``clock``: the clock id, and — for ``OFFSET`` the offset, for ``RATE`` the
      ppm bounded by :data:`MAX_SLEW_PPM` — the magnitude.

    The result is never empty, because every family has at least a target
    selector.
    """
    grammar: tuple[PrimitiveParam, ...]
    if isinstance(primitive, KernelPrimitive):
        grammar = _kernel_grammar(primitive)
    elif isinstance(primitive, IOPrimitive):
        grammar = _io_grammar(primitive)
    elif isinstance(primitive, JVMPrimitive):
        grammar = _jvm_grammar(primitive)
    else:
        assert isinstance(primitive, ClockPrimitive)  # every family is one of the four
        grammar = _clock_grammar(primitive)
    if not grammar:  # pragma: no cover - defensive: every family appends a selector
        raise InvariantViolationError(
            "lowlevel.empty_grammar",
            f"{primitive.id!r} has no parameter grammar: a request could not be "
            "distinguished from any other request for it",
        )
    return grammar


def _errno_choices() -> tuple[str, ...]:
    """The closed errno vocabulary, sorted once."""
    return tuple(sorted(code.value for code in ErrorCode))


def _kernel_grammar(primitive: KernelPrimitive) -> tuple[PrimitiveParam, ...]:
    """``kernel``: target syscall, attach scope, and the mode's own quantity."""
    grammar = [
        _enum_param("syscall", primitive.syscalls, required=True),
        _enum_param(
            "attachment",
            (ReverseAttachment.PROCESS.value, ReverseAttachment.THREAD.value),
            default=primitive.attachment.value,
        ),
    ]
    if primitive.mode is KernelInjectionMode.ERRNO_RETURN:
        assert primitive.errno_name is not None  # narrowed by the descriptor's validator
        grammar.append(_enum_param("errno", _errno_choices(), default=primitive.errno_name.value))
    elif primitive.mode is KernelInjectionMode.LATENCY_DELAY:
        grammar.append(
            _ms_param(
                "latency_ms",
                primitive.latency_ms,
                primitive.max_safe_duration_s * 1000,
            )
        )
    else:
        grammar.append(
            _enum_param(
                "mutation",
                RETURN_MUTATIONS,
                default=primitive.return_mutation,
                required=True,
            )
        )
    return tuple(grammar)


def _io_grammar(primitive: IOPrimitive) -> tuple[PrimitiveParam, ...]:
    """``io``: the path selector under the descriptor's own name, and the quantity.

    The path parameter keeps the name the descriptor gave it — ``device`` for the
    device-mapper target, ``path`` for a mount — so a request reads the way the
    descriptor documented it rather than through a renamed field.
    """
    grammar = [
        PrimitiveParam(
            name=primitive.path_param,
            kind=ParamKind.PATH,
            required=True,
            default=primitive.default_path,
        ),
        _enum_param(
            "operation",
            (op.value for op in IoOperation),
            default=primitive.operation.value,
        ),
    ]
    if primitive.mode is IoMode.DELAY:
        grammar.append(
            _ms_param("delay_ms", primitive.delay_ms, primitive.max_safe_duration_s * 1000)
        )
    elif primitive.mode is IoMode.ERROR:
        assert primitive.error_code is not None  # narrowed by the descriptor's validator
        grammar.append(_enum_param("errno", _errno_choices(), default=primitive.error_code.value))
    return tuple(grammar)


def _name_param(name: str, value: str | None) -> PrimitiveParam:
    """A required identifier parameter — a Java class, method or exception class."""
    return PrimitiveParam(
        name=name,
        kind=ParamKind.IDENTIFIER,
        required=True,
        default=value,
    )


def _jvm_grammar(primitive: JVMPrimitive) -> tuple[PrimitiveParam, ...]:
    """``jvm``: the target method, the attach channel, and the mode's own quantity."""
    grammar = [
        _name_param("target_class", primitive.target_class),
        _name_param("target_method", primitive.target_method),
        _enum_param(
            "instrumentation",
            (tool.value for tool in JVMInstrumentation),
            default=primitive.instrumentation.value,
        ),
    ]
    if primitive.mode is JvmInjectionMode.EXCEPTION_INJECT:
        grammar.append(_name_param("exception_class", primitive.exception_class))
    elif primitive.mode is JvmInjectionMode.METHOD_DELAY:
        grammar.append(
            _ms_param("delay_ms", primitive.delay_ms, primitive.max_safe_duration_s * 1000)
        )
    elif primitive.mode in SCALING_JVM_MODES:
        grammar.append(
            PrimitiveParam(
                name="pressure_units",
                kind=ParamKind.INTEGER,
                unit=_PRESSURE_UNITS[primitive.mode].value,
                required=True,
                default=primitive.pressure_units,
                minimum=MIN_MAGNITUDE,
                maximum=int(_MAX_PRESSURE_UNITS),
            )
        )
    return tuple(grammar)


def _clock_grammar(primitive: ClockPrimitive) -> tuple[PrimitiveParam, ...]:
    """``clock``: the clock, and the offset or slew the mode applies."""
    grammar = [
        _enum_param(
            "clock_id",
            (clock.value for clock in ClockId),
            default=primitive.clock_id.value,
        )
    ]
    window_ms = int(primitive.max_safe_duration_s * 1000)
    if primitive.mode is ClockMode.OFFSET:
        grammar.append(
            PrimitiveParam(
                name="offset_ms",
                kind=ParamKind.INTEGER,
                unit="ms",
                required=True,
                default=primitive.offset_ms,
                minimum=-window_ms,
                maximum=window_ms,
            )
        )
    elif primitive.mode is ClockMode.RATE:
        grammar.append(
            PrimitiveParam(
                name="rate_ppm",
                kind=ParamKind.INTEGER,
                unit="ppm",
                required=True,
                default=primitive.rate_ppm,
                minimum=-MAX_SLEW_PPM,
                maximum=MAX_SLEW_PPM,
            )
        )
    return tuple(grammar)


#: What a mode with no tunable amount says about itself, in one sentence.
_NO_AMOUNT: Final[str] = "the mode applies a fixed transformation with no tunable amount"

#: The one parameter that carries a family/mode's magnitude, or nothing.
#:
#: A table rather than a chain of ``isinstance`` tests because there are two
#: readers of the same question and they must not answer it differently:
#: :func:`magnitude_holder` (which tells a person) and :func:`_magnitude_from`
#: (which reads the value). Splitting the decision into a "where is it" and a
#: "what is it" is how a magnitude ends up named in a report and read from a
#: different field at injection time.
_MAGNITUDE_PARAM_BY_FAMILY: Final[Mapping[PrimitiveFamily, Mapping[object, str]]] = (
    MappingProxyType(
        {
            PrimitiveFamily.KERNEL: MappingProxyType(
                {KernelInjectionMode.LATENCY_DELAY: "latency_ms"}
            ),
            PrimitiveFamily.IO: MappingProxyType({IoMode.DELAY: "delay_ms"}),
            PrimitiveFamily.JVM: MappingProxyType(
                {
                    JvmInjectionMode.METHOD_DELAY: "delay_ms",
                    JvmInjectionMode.ALLOCATION_PRESSURE: "pressure_units",
                    JvmInjectionMode.GC_PRESSURE: "pressure_units",
                    JvmInjectionMode.THREAD_PRESSURE: "pressure_units",
                }
            ),
            PrimitiveFamily.CLOCK: MappingProxyType(
                {ClockMode.OFFSET: "offset_ms", ClockMode.RATE: "rate_ppm"}
            ),
        }
    )
)

#: Unit of each magnitude parameter. ``pressure_units`` is absent on purpose: its
#: unit depends on the mode, so it is read from :data:`_PRESSURE_UNITS` instead of
#: being guessed here.
_MAGNITUDE_UNIT_BY_PARAM: Final[Mapping[str, str]] = MappingProxyType(
    {"latency_ms": "ms", "delay_ms": "ms", "offset_ms": "ms", "rate_ppm": "ppm"}
)


def _magnitude_field(primitive: LowLevelPrimitive) -> str:
    """The parameter that carries this primitive's magnitude, or ``""``."""
    return _MAGNITUDE_PARAM_BY_FAMILY[primitive.family].get(primitive.mode, "")


def magnitude_holder(primitive: LowLevelPrimitive) -> str:
    """Where this primitive's magnitude lives, in words.

    Three answers, and the third is the interesting one. A scaling mode carries
    its own magnitude field. A mode with no amount to scale by names itself — and
    an *error* mode says so more precisely, because the errno it returns is a
    code rather than a size and reading its absence as a missing parameter would
    be wrong. A mode whose amount belongs to the *backing catalog entry* names
    that entry, so a reader learns that ``io.capacity_exhaustion`` takes its size
    from ``fs.fill``'s parameters rather than from a field of its own.
    """
    field = _magnitude_field(primitive)
    if field:
        return f"the primitive's own {field}"
    if isinstance(primitive, IOPrimitive) and primitive.mode is IoMode.ERROR:
        return "the errno it returns, which is a code rather than an amount"
    if primitive.existing_fault_id is not None:
        return f"the parameters of the backing catalog entry {primitive.existing_fault_id}"
    return _NO_AMOUNT


def resolve_params(
    primitive: LowLevelPrimitive, params: Mapping[str, object]
) -> tuple[tuple[PrimitiveParam, str | int], ...]:
    """Check *params* against *primitive*'s grammar and return them resolved.

    A total, pure check that **refuses** rather than repairs: an unknown
    parameter, a missing required one, a value outside a closed vocabulary, a
    magnitude of zero, and a magnitude that outlasts the descriptor's own window
    are five different mistakes and none of them is silently corrected. A grammar
    that filled in a default for a value the operator supplied wrongly would be
    inventing an injection nobody asked for.

    Raises:
        InvariantViolationError: With rule ``lowlevel.parameter_out_of_grammar``
            and a message naming the parameter and what was wrong with it.
    """
    grammar = {param.name: param for param in parameter_grammar(primitive)}
    unknown = sorted(set(params) - set(grammar))
    if unknown:
        raise InvariantViolationError(
            "lowlevel.parameter_out_of_grammar",
            f"{primitive.id!r} accepts no parameter(s) {unknown}; its grammar is "
            + "; ".join(
                f"{param.name}: {param.describe()}" for param in parameter_grammar(primitive)
            ),
        )
    resolved: list[tuple[PrimitiveParam, str | int]] = []
    for name, param in grammar.items():
        supplied = params.get(name, param.default)
        if supplied is None:
            if param.required:
                raise InvariantViolationError(
                    "lowlevel.parameter_out_of_grammar",
                    f"{primitive.id!r} requires parameter {name!r} and no default exists for it",
                )
            continue
        if param.kind is ParamKind.INTEGER:
            if isinstance(supplied, bool) or not isinstance(supplied, int):
                raise InvariantViolationError(
                    "lowlevel.parameter_out_of_grammar",
                    f"{name!r} of {primitive.id!r} must be an integer number of "
                    f"{param.unit}, not {supplied!r}",
                )
            assert param.minimum is not None and param.maximum is not None
            if not param.minimum <= supplied <= param.maximum:
                raise InvariantViolationError(
                    "lowlevel.parameter_out_of_grammar",
                    f"{name!r}={supplied} of {primitive.id!r} is outside "
                    f"{param.minimum}..{param.maximum} {param.unit}",
                )
            resolved.append((param, supplied))
            continue
        if not isinstance(supplied, str):
            raise InvariantViolationError(
                "lowlevel.parameter_out_of_grammar",
                f"{name!r} of {primitive.id!r} must be a string, not {supplied!r}",
            )
        if not param._within(supplied):
            raise InvariantViolationError(
                "lowlevel.parameter_out_of_grammar",
                f"{name!r}={supplied!r} of {primitive.id!r} is not an accepted value; "
                f"expected {param.describe()}",
            )
        resolved.append((param, supplied))
    return tuple(resolved)


def specification_for(
    primitive: LowLevelPrimitive, params: Mapping[str, object]
) -> AttachSpecification:
    """The attachment *primitive* would perform for *params*.

    Pure and total over a checked request: it resolves the grammar, then reads
    the descriptor. It is a description, and the only way anything could be
    injected is if a caller took this value and performed an operation — which no
    code in this repository does, for any of the 22 primitives.

    :raises InvariantViolationError: ``lowlevel.parameter_out_of_grammar``, from
        :func:`resolve_params`.
    """
    resolved = {param.name: value for param, value in resolve_params(primitive, params)}
    magnitude, unit = _magnitude_from(primitive, resolved)
    return AttachSpecification(
        primitive_id=primitive.id,
        family=primitive.family.value,
        mode=_mode_of(primitive),
        mechanism=(
            primitive.missing.mechanism if primitive.missing is not None else primitive.family.value
        ),
        targets=tuple(sorted((name, str(value)) for name, value in resolved.items())),
        magnitude=magnitude,
        unit=unit,
        undo=primitive.reversibility_statement.undo,
        residue_probes=tuple(check.probe for check in primitive.residue_checks),
    )


def _mode_of(primitive: LowLevelPrimitive) -> str:
    """The descriptor's mode. Every family names its own field ``mode``."""
    return str(getattr(primitive.mode, "value", primitive.mode))


def _magnitude_from(
    primitive: LowLevelPrimitive, resolved: Mapping[str, str | int]
) -> tuple[int | None, str]:
    """The one magnitude a request carries, with its unit — or ``(None, "")``.

    Deliberately singular. A request that could carry two magnitudes would give
    the inertness guard two things to compare and would let a mechanism choose
    which one to honour, and a mechanism that may choose is a mechanism that may
    choose wrong.
    """
    field = _magnitude_field(primitive)
    if not field or field not in resolved:
        return None, ""
    if field == "pressure_units":
        assert isinstance(primitive, JVMPrimitive)  # the only family declaring it
        return int(resolved[field]), _PRESSURE_UNITS[primitive.mode].value
    return int(resolved[field]), _MAGNITUDE_UNIT_BY_PARAM[field]


# ── queries over the declared set ────────────────────────────────────────────


def primitive_by_id(primitive_id: str) -> LowLevelPrimitive | None:
    """The primitive with this id, or ``None``. Total; never raises."""
    return PRIMITIVES.get(primitive_id)


def descriptor_for(primitive_id: str) -> LowLevelPrimitive:
    """The primitive with this id.

    Raises:
        KeyError: If no such primitive is declared. Use
            :func:`primitive_by_id` where absence is an ordinary answer.
    """
    return PRIMITIVES[primitive_id]


def injectable_primitives(
    surface: SubstrateSurface = CURRENT_SUBSTRATE,
) -> tuple[LowLevelPrimitive, ...]:
    """Every primitive *surface* can inject today, in id order.

    A small set, and every member names the existing catalog entry that already
    carries its mechanism. It is not a list of new capabilities.
    """
    return tuple(
        sorted(
            (p for p in PRIMITIVES.values() if p.substrate_verdict(surface)),
            key=lambda p: p.id,
        )
    )


def missing_mechanism_for(
    primitive_id: str, surface: SubstrateSurface = CURRENT_SUBSTRATE
) -> MissingMechanism | None:
    """The named mechanism that blocks this primitive, or ``None`` if nothing does."""
    primitive = PRIMITIVES.get(primitive_id)
    if primitive is None:
        return None
    if primitive.substrate_verdict(surface):
        return None
    return primitive.missing


class ConsistencyProblem(BaseModel):
    """One cross-claim inconsistency, as data rather than an exception."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    subject: str
    detail: str


def registry_problems() -> tuple[ConsistencyProblem, ...]:
    """Every way the declared set disagrees with itself or with the substrate.

    Pure, total, and deliberately **not** run at import. ``domain/catalog.py``
    validates at import and a non-conforming entry there breaks ``import mayhem``
    for the whole package; a new registry that nobody imports should not be able
    to do the same thing. This returns the problems instead of raising, and
    ``tests/unit/test_lowlevel.py`` asserts it is empty.
    """
    problems: list[ConsistencyProblem] = []
    for primitive in PRIMITIVES.values():
        for other_id in sorted(primitive.incompatible_with):
            if other_id not in PRIMITIVES:
                problems.append(
                    ConsistencyProblem(
                        subject=primitive.id,
                        detail=(f"declares incompatibility with unknown primitive {other_id!r}"),
                    )
                )
        problems.extend(_substrate_problems(primitive, CURRENT_SUBSTRATE))
    ids = list(PRIMITIVES)
    if len(set(ids)) != len(ids):
        problems.append(
            ConsistencyProblem(subject="registry", detail="primitive ids must be unique")
        )
    return tuple(problems)


def _substrate_problems(
    primitive: LowLevelPrimitive, surface: SubstrateSurface
) -> list[ConsistencyProblem]:
    """The two honesty checks over one primitive, as problems."""
    try:
        validate_substrate_claims(primitive, surface)
    except InvariantViolationError as exc:
        return [ConsistencyProblem(subject=primitive.id, detail=str(exc))]
    return []


def validate_substrate_claims(
    primitive: LowLevelPrimitive,
    surface: SubstrateSurface = CURRENT_SUBSTRATE,
) -> None:
    """Refuse a descriptor whose ``missing`` declaration does not match reality.

    Two directions, because a declaration is a claim about the substrate and can
    be wrong either way:

    * **Under-claiming** — the surface produces a gap the descriptor never
      declared. A descriptor asking for tooling nothing can evaluate while
      claiming nothing is missing is the exact shape of the ``ip`` bug, and it is
      a refusal, not a warning.
    * **Over-claiming** — the descriptor declares a mechanism missing while the
      surface satisfies every demand. That is the shape of an "unimplemented"
      excuse covering a working mechanism, and the plan's own refusals exist
      because that direction is the one that erodes trust fastest.

    Raises:
        InvariantViolationError: If the declaration and the surface disagree.
    """
    verdict = primitive.substrate_verdict(surface)
    gaps = verdict.gaps
    if not gaps and primitive.missing is None:
        return
    if not gaps and primitive.missing is not None:
        raise InvariantViolationError(
            "lowlevel.over_declared_missing",
            f"{primitive.id!r} declares the missing mechanism "
            f"{primitive.missing.mechanism!r}, but every demand it declares is "
            f"satisfied by the surface it was asked about",
        )
    if gaps and primitive.missing is None:
        raise InvariantViolationError(
            "lowlevel.undeclared_missing",
            f"{primitive.id!r} is not injectable on the surface it was asked "
            f"about and declares no missing mechanism; first unmet demand is "
            f"{gaps[0].demand} ({gaps[0].reason.value})",
        )
    assert primitive.missing is not None  # narrowed by the guards above
    uncovered = [gap for gap in gaps if not primitive.missing.covers(gap)]
    if uncovered:
        first = uncovered[0]
        raise InvariantViolationError(
            "lowlevel.uncovered_gap",
            f"{primitive.id!r} declares the missing mechanism "
            f"{primitive.missing.mechanism!r}, which does not account for demand "
            f"{first.demand} ({first.reason.value}); every unmet demand must be "
            f"named or the descriptor is a partial claim presented as a whole",
        )
    if primitive.maturity_floor is not MaturityLevel.EXPERIMENTAL:
        raise InvariantViolationError(
            "lowlevel.unearned_maturity",
            f"{primitive.id!r} is not injectable on the surface it was asked "
            f"about, so it cannot claim {primitive.maturity_floor.value!r}",
        )
