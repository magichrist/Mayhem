"""Plan 04 Phase 1 — low-level primitive descriptors: what is declared, and what is not.

Why this file exists
--------------------
``domain/lowlevel.py`` makes one class of claim: *this is what a low-level
mechanism would need, and here is the honest answer about whether mayhem can
inject it today*. A claim like that is worth nothing unless the thing that
checks it is not the thing that wrote it, so the groups here are:

* **the restatement guard.** ``CURRENT_SUBSTRATE`` is a second literal that
  claims to agree with ``agents/impact.py``'s three tables, the ``Capability``
  enum and the toolkit manifests. A domain module may not import any of them, so
  a test is the only thing that can catch the copy drifting. This is the guard
  that matters most: it is the difference between a checkable demand and a wish.
* **descriptor validation.** Every descriptor is pinned against the rules that
  make it admissible, and against the three TOTAL category maps in
  ``domain/catalog.py`` that a bare ``FaultCategory`` would have to appear in.
* **checkability of every demand.** Each declared bin/cap/tool is classified
  against the real gate tables, and an uncheckable demand must arrive with the
  matching missing mechanism.
* **the negative controls.** Four forgeries the type must not admit — a demand no
  manifest provides with nothing declared missing, a descriptor with no
  reversibility statement, an irreversible primitive claiming a compensation
  template, and a primitive with no residue check — plus the two cross-claim
  forgeries (under- and over-declared ``missing``).

The last test re-states the domain law locally: this module may not import the
toolkit, agents, controller, infra, or the IO modules. ``pyproject.toml``'s
import-linter contract enforces the same thing in CI, but that check needs an
extra dependency, so the guard also lives here.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest
from pydantic import ValidationError

import mayhem.domain.lowlevel as lowlevel_module
from mayhem.agents import impact
from mayhem.domain import catalog as catalog_module
from mayhem.domain.capabilities import Capability
from mayhem.domain.catalog import CATALOG, definition_for
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.faults import FaultCategory, MaturityLevel, Reversibility
from mayhem.domain.lowlevel import (
    CURRENT_SUBSTRATE,
    ERNO_NUMBERS,
    PRIMITIVES,
    REUSED_CATEGORY_BY_FAMILY,
    CapabilityGap,
    ClockPrimitive,
    ErrorCode,
    GapReason,
    IOPrimitive,
    JVMPrimitive,
    KernelPrimitive,
    MissingCode,
    MissingMechanism,
    PrimitiveFamily,
    ResidueCheck,
    ResidueFacet,
    ReverseAttachment,
    ReversibilityStatement,
    SubstrateSurface,
    descriptor_for,
    injectable_primitives,
    missing_mechanism_for,
    primitive_by_id,
    registry_problems,
    validate_substrate_claims,
)
from mayhem.domain.risks import RiskLevel
from mayhem.toolkit.registry import default_registry

ALL_PRIMITIVES = tuple(PRIMITIVES.values())
ALL_IDS = tuple(sorted(PRIMITIVES))

#: The four that today's substrate can inject. Pinned as a literal so a
#: descriptor that quietly becomes injectable — or stops being one — is a test
#: failure rather than a docstring that quietly becomes wrong.
INJECTABLE_IDS = (
    "clock.realtime_offset",
    "io.capacity_exhaustion",
    "io.filesystem_read_only",
    "io.inode_exhaustion",
)

_CATALOG_IDS = frozenset(d.id for d in CATALOG)


def _reversible(**overrides: object) -> ReversibilityStatement:
    return ReversibilityStatement(
        reversibility=Reversibility.REVERSIBLE,
        undo="detach the mechanism",
        verification="a canary call behaves as it did before the injection",
        compensation_template="probe.undo",
        **(overrides or {}),
    )


def _minimal_kernel(**overrides: object) -> dict[str, object]:
    """A valid ``KernelPrimitive`` payload, so a test can break one field."""
    base: dict[str, object] = {
        "id": "kernel.probe",
        "family": PrimitiveFamily.KERNEL,
        "title": "A probe kernel primitive",
        "summary": "A summary long enough to satisfy the descriptor contract.",
        "category": FaultCategory.PROCESS,
        "risk": RiskLevel.HIGH,
        "max_safe_duration_s": 60.0,
        "reversibility_statement": _reversible(),
        "residue_checks": (
            ResidueCheck(
                facet=ResidueFacet.ATTACHMENT,
                probe="read the tracefs kprobe table",
                expectation="no mayhem-owned entry remains",
            ),
        ),
        "syscalls": frozenset({"read"}),
        "mode": "latency_delay",
        "latency_ms": 2500,
        "loader": "probe-loader",
    }
    base.update(overrides)
    return base


def _minimal_io(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "id": "io.probe",
        "family": PrimitiveFamily.IO,
        "title": "A probe IO primitive",
        "summary": "A summary long enough to satisfy the descriptor contract.",
        "category": FaultCategory.STORAGE,
        "risk": RiskLevel.MEDIUM,
        "max_safe_duration_s": 60.0,
        "reversibility_statement": _reversible(),
        "residue_checks": (
            ResidueCheck(
                facet=ResidueFacet.FILESYSTEM,
                probe="digest a known file",
                expectation="digest matches the pre-injection record",
            ),
        ),
        "operation": "read",
        "mode": "delay",
        "delay_ms": 1500,
        "shim": "fuse",
        "path_param": "path",
        "default_path": "/tmp",
    }
    base.update(overrides)
    return base


# ── 1. the restatement guard ────────────────────────────────────────────────


def test_probe_bins_restatement_matches_the_impact_gate() -> None:
    assert CURRENT_SUBSTRATE.probe_bins == frozenset(impact._PROBE_BINS)


def test_cap_bit_restatement_matches_the_impact_gate() -> None:
    assert CURRENT_SUBSTRATE.cap_bits == frozenset(impact._CAP_BITS)


def test_installable_bin_restatement_matches_the_impact_gate() -> None:
    assert CURRENT_SUBSTRATE.installable_bins == frozenset(impact._PM_PACKAGES)


def test_host_tool_restatement_matches_the_impact_gate() -> None:
    assert CURRENT_SUBSTRATE.host_tools == frozenset(impact._HOST_TOOL_BINS)


def test_the_restatement_is_checked_at_impact_import_time_not_only_by_tests() -> None:
    """The drift guard is an import, so a stale mirror is a broken import.

    The four tests above only run when somebody runs them. ``impact.py``
    re-checks the same four tables when it is imported, which means an edit to
    a table there fails at the edit rather than leaving the domain asserting a
    capability the gate cannot see behind a green suite.
    """
    assert impact.validate_substrate_mirrors() == ()


def test_a_diverged_restatement_is_named_not_merely_counted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Negative control: the guard must *name* what drifted, in both directions.

    Two failure shapes, both real. A bin added to ``_PROBE_BINS`` and not
    mirrored is the ``ip`` bug: the fault gates INERT forever. A bin the domain
    still claims after it was dropped from the gate is worse — the domain
    advertises a capability the gate can never confirm.
    """
    monkeypatch.setattr(
        impact,
        "_SUBSTRATE_MIRRORS",
        (
            (
                "_PROBE_BINS",
                frozenset(impact._PROBE_BINS) | {"strace"},
                CURRENT_SUBSTRATE.probe_bins,
            ),
            (
                "_CAP_BITS",
                frozenset(impact._CAP_BITS),
                CURRENT_SUBSTRATE.cap_bits | {"SYS_PTRACE"},
            ),
        ),
    )
    problems = impact.validate_substrate_mirrors()

    assert len(problems) == 2
    assert "strace" in problems[0]
    assert "_PROBE_BINS" in problems[0]
    assert "SYS_PTRACE" in problems[1]
    assert "CURRENT_SUBSTRATE" in problems[1]


def test_every_probeable_bin_is_still_either_installable_or_a_named_exception() -> None:
    """The two bins sets disagree in exactly two known ways, and only two.

    ``_PROBE_BINS`` holds the six package managers, which have no
    ``_PM_PACKAGES`` row because they *are* the installer, and ``python3``,
    which ``ContainerRuntime.has_bin`` treats as an alias for ``python`` and
    therefore needs no row of its own. Anything else in ``_PROBE_BINS`` with no
    row is a bin the gate can see but ``mayhem prepare dependencies install`` can
    never supply — the third trap, and the one this file exists to keep visible.
    """
    expected_exceptions = set(impact._PACKAGE_MANAGERS) | {"python3"}
    unexplained = CURRENT_SUBSTRATE.probe_bins - CURRENT_SUBSTRATE.installable_bins
    assert unexplained == expected_exceptions


def test_capability_restatement_covers_every_handshake_capability() -> None:
    assert CURRENT_SUBSTRATE.capabilities == frozenset(Capability)


def test_manifest_capability_restatement_matches_the_default_registry() -> None:
    provided: set[str] = set()
    for manifest in default_registry().manifests:
        provided.update(manifest.provides)
    assert CURRENT_SUBSTRATE.manifest_capabilities == frozenset(provided)


# ── 2. descriptor validation ────────────────────────────────────────────────


def test_the_registry_declares_every_plan_family() -> None:
    assert {p.family for p in ALL_PRIMITIVES} == set(PrimitiveFamily)
    assert len(ALL_IDS) == len(ALL_PRIMITIVES)


@pytest.mark.parametrize("primitive_id", ALL_IDS)
def test_a_primitive_declares_every_field_the_plan_requires(primitive_id: str) -> None:
    """Pins the plan-04 "Safety requirements" list, one field at a time."""
    primitive = descriptor_for(primitive_id)
    assert primitive.required_caps or primitive.probe_bins or primitive.existing_fault_id
    assert primitive.missing is not None or primitive.existing_fault_id is not None
    assert primitive.reversibility_statement.undo.strip()
    assert primitive.reversibility_statement.verification.strip()
    assert primitive.residue_checks
    assert primitive.max_safe_duration_s > 0
    assert primitive.incompatible_with == primitive.incompatible_with  # a frozenset


@pytest.mark.parametrize("primitive_id", ALL_IDS)
def test_a_primitive_id_is_not_a_fault_id(primitive_id: str) -> None:
    """The five-registry contract: this lane adds no fault id.

    ``PRIMITIVES`` is a descriptor set, not a catalog. If an id ever appeared in
    both, the catalog's exhaustive tests would start deriving claims about a
    descriptor that has no executor, no template and no REQUIREMENTS row.
    """
    assert primitive_id not in _CATALOG_IDS


@pytest.mark.parametrize("primitive_id", ALL_IDS)
def test_a_primitive_reuses_a_category_with_entries_in_all_three_maps(primitive_id: str) -> None:
    """A bare category is an import-time ``KeyError`` in ``domain/catalog.py``.

    Every category a descriptor reuses is therefore checked against all three
    TOTAL maps, so Phase 1 can never be the commit that adds the fourth.
    """
    category = descriptor_for(primitive_id).category
    assert category in catalog_module._FAILURE_DOMAIN_BY_CATEGORY
    assert category in catalog_module._VERIFICATION_BY_CATEGORY
    assert category in catalog_module._EFFECT_BY_CATEGORY


def test_the_reused_category_mapping_names_only_existing_categories() -> None:
    """Every reused value is a ``FaultCategory`` member, i.e. it already existed.

    Not a type tautology: it is the property that matters. A member of that enum
    is what ``_FAILURE_DOMAIN_BY_CATEGORY`` and friends are keyed by, so naming
    one is safe; *adding* one is the import-time ``KeyError``. The mapping cannot
    add one, and this is the check that says so in one place.
    """
    assert set(REUSED_CATEGORY_BY_FAMILY) == set(PrimitiveFamily)
    for family, category in REUSED_CATEGORY_BY_FAMILY.items():
        assert category in set(FaultCategory), f"{family.value} names a non-category"


@pytest.mark.parametrize("primitive_id", ALL_IDS)
def test_a_primitive_category_is_its_family_reused_category(primitive_id: str) -> None:
    primitive = descriptor_for(primitive_id)
    assert primitive.category is REUSED_CATEGORY_BY_FAMILY[primitive.family]


@pytest.mark.parametrize("primitive_id", ALL_IDS)
def test_a_high_risk_primitive_respects_the_catalog_duration_ceiling(primitive_id: str) -> None:
    primitive = descriptor_for(primitive_id)
    if primitive.risk.at_least(RiskLevel.HIGH):
        assert primitive.max_safe_duration_s <= 600.0


@pytest.mark.parametrize("primitive_id", ALL_IDS)
def test_an_existing_fault_reference_resolves_to_an_active_entry(primitive_id: str) -> None:
    referenced = descriptor_for(primitive_id).existing_fault_id
    if referenced is None:
        return
    definition = definition_for(referenced)
    assert not definition.catalog_only, f"{referenced} refuses to execute; do not cite it"
    assert definition.category is descriptor_for(primitive_id).category


@pytest.mark.parametrize("primitive_id", ALL_IDS)
def test_every_near_miss_and_anchor_names_a_real_fault(primitive_id: str) -> None:
    """A near-miss that does not resolve is an unverifiable claim."""
    missing = descriptor_for(primitive_id).missing
    if missing is None:
        return
    for near_miss in missing.near_misses:
        assert near_miss in _CATALOG_IDS, f"{primitive_id}: {near_miss!r} is not a fault id"
        assert near_miss != primitive_id
    if missing.anchor_fault_id is not None:
        assert missing.anchor_fault_id in _CATALOG_IDS


@pytest.mark.parametrize("primitive_id", ALL_IDS)
def test_an_anchor_is_a_catalog_only_refusal_with_the_authoritative_prefix(
    primitive_id: str,
) -> None:
    """The existing refusals stay authoritative; a descriptor cites, never edits."""
    missing = descriptor_for(primitive_id).missing
    if missing is None or missing.anchor_fault_id is None:
        return
    anchored = definition_for(missing.anchor_fault_id)
    assert anchored.catalog_only
    assert (anchored.refusal_reason or "").startswith("catalog.unsupported")


def test_the_errno_table_is_total_unique_and_spot_checked() -> None:
    assert set(ERNO_NUMBERS) == set(ErrorCode)
    assert len(set(ERNO_NUMBERS.values())) == len(ERNO_NUMBERS)
    # asm-generic/errno.h: EIO=5, ENOSPC=28, EACCES=13, ETIMEDOUT=110.
    assert ERNO_NUMBERS[ErrorCode.EIO] == 5
    assert ERNO_NUMBERS[ErrorCode.ENOSPC] == 28
    assert ERNO_NUMBERS[ErrorCode.EACCES] == 13
    assert ERNO_NUMBERS[ErrorCode.ETIMEDOUT] == 110


def test_primitive_lookups_are_total() -> None:
    assert primitive_by_id("kernel.syscall_errno") is not None
    assert primitive_by_id("kernel.does_not_exist") is None
    assert missing_mechanism_for("kernel.does_not_exist") is None
    with pytest.raises(KeyError):
        descriptor_for("kernel.does_not_exist")


def test_the_declared_registry_is_internally_consistent() -> None:
    assert registry_problems() == ()


def test_the_incompatibility_relation_is_symmetric_by_construction() -> None:
    for primitive in ALL_PRIMITIVES:
        for other_id in primitive.incompatible_ids():
            other = descriptor_for(other_id)
            assert primitive.id in other.incompatible_ids()
        assert primitive.id not in primitive.incompatible_ids()


# ── 3. the pure predicate ───────────────────────────────────────────────────


def test_the_injectable_set_is_pinned() -> None:
    assert tuple(p.id for p in injectable_primitives()) == INJECTABLE_IDS


@pytest.mark.parametrize("primitive_id", INJECTABLE_IDS)
def test_an_injectable_primitive_names_the_working_fault_that_already_carries_it(
    primitive_id: str,
) -> None:
    """Phase 1 builds no mechanism, so an injectable primitive is a *reference*.

    Without this, "injectable" would be a claim that no catalog id backs — the
    green-tests-broken-behaviour shape ``docs/new-faults/OUTCOME.md`` warns about.
    """
    primitive = descriptor_for(primitive_id)
    assert primitive.existing_fault_id is not None
    assert primitive.missing is None
    assert primitive.maturity_floor is MaturityLevel.VERIFIED_UNIT


def test_a_non_injectable_primitive_names_what_is_missing() -> None:
    for primitive in ALL_PRIMITIVES:
        verdict = primitive.substrate_verdict()
        if verdict.injectable:
            continue
        assert primitive.missing is not None
        assert verdict.gaps
        assert missing_mechanism_for(primitive.id) is not None


def test_the_verdict_is_pure_and_repeatable() -> None:
    for primitive in ALL_PRIMITIVES:
        first = primitive.substrate_verdict()
        second = primitive.substrate_verdict()
        assert first == second
        assert first.primitive_id == primitive.id
        assert bool(first) is first.injectable


def test_a_verdict_names_the_first_unmet_demand() -> None:
    primitive = descriptor_for("kernel.syscall_errno")
    verdict = primitive.substrate_verdict()
    assert not verdict.injectable
    assert verdict.gaps[0].demand == "bin:bpftool"
    assert "bin:bpftool" in verdict.detail


def test_an_unachievable_primitive_is_distinguished_from_an_unbuilt_one() -> None:
    """``NOT_STEPPABLE`` means no mechanism would do, not "not yet"."""
    unachievable = {
        p.id for p in ALL_PRIMITIVES if p.missing and p.missing.unachievable_substrate
    }
    assert unachievable == {"clock.monotonic_offset", "clock.monotonic_freeze"}
    for primitive_id in unachievable:
        missing = descriptor_for(primitive_id).missing
        assert missing is not None
        assert missing.code is MissingCode.NOT_STEPPABLE
    unbuilt = {
        p.id
        for p in ALL_PRIMITIVES
        if p.missing and not p.missing.unachievable_substrate
    }
    assert unbuilt, "the plan's families are all unbuilt, and that must stay visible"


# ── 4. checkability of every declared demand ────────────────────────────────


@pytest.mark.parametrize("primitive_id", ALL_IDS)
def test_every_declared_demand_is_classified_against_the_real_tables(primitive_id: str) -> None:
    """A demand the gate cannot evaluate is refused, or it is declared missing.

    This is the checkability contract, stated directly: every bin is either in
    ``_PROBE_BINS`` or the descriptor's missing mechanism covers
    ``BIN_NOT_PROBED``; every cap bit is either in ``_CAP_BITS`` or covered;
    every tool capability is either declared by a manifest or covered.
    """
    primitive = descriptor_for(primitive_id)
    verdict = primitive.substrate_verdict()
    reasons = primitive.missing.covers_reasons if primitive.missing else frozenset()

    for binary in primitive.probe_bins:
        if not impact._PROBE_BINS or binary not in impact._PROBE_BINS:
            assert GapReason.BIN_NOT_PROBED in reasons
        if binary in impact._PROBE_BINS and binary not in impact._PM_PACKAGES:
            assert GapReason.BIN_NOT_INSTALLABLE in reasons
    for cap_bit in primitive.probe_caps:
        if cap_bit not in impact._CAP_BITS:
            assert GapReason.CAP_BIT_UNDEFINED in reasons
    for binary in primitive.host_tools:
        if binary not in impact._HOST_TOOL_BINS:
            assert GapReason.HOST_TOOL_ABSENT in reasons
    for capability in primitive.tool_capabilities:
        if not CURRENT_SUBSTRATE.is_manifested(capability):
            assert GapReason.TOOL_NOT_MANIFESTED in reasons
    # Every produced gap is a real one: no descriptor manufactures a reason the
    # tables do not support.
    for gap in verdict.gaps:
        assert gap.reason in GapReason


@pytest.mark.parametrize("primitive_id", ALL_IDS)
def test_the_declared_reason_set_is_exactly_what_the_surface_produced(primitive_id: str) -> None:
    """Not a superset, not a subset: the declaration and the gate must agree."""
    primitive = descriptor_for(primitive_id)
    produced = {gap.reason for gap in primitive.substrate_gaps(CURRENT_SUBSTRATE)}
    declared = primitive.missing.covers_reasons if primitive.missing else frozenset()
    assert produced == declared


@pytest.mark.parametrize("primitive_id", ALL_IDS)
def test_no_primitive_demands_a_probeable_bin_it_cannot_install_silently(
    primitive_id: str,
) -> None:
    """The third trap, as a one-line invariant on the declared set.

    A bin that is probed but has no ``_PM_PACKAGES`` row can never be
    auto-installed. No descriptor in this lane creates one; if a future one does,
    it has to say so.
    """
    primitive = descriptor_for(primitive_id)
    silent = {
        binary
        for binary in primitive.probe_bins
        if binary in impact._PROBE_BINS and binary not in impact._PM_PACKAGES
    }
    assert not silent


@pytest.mark.parametrize("primitive_id", ALL_IDS)
def test_every_descriptor_round_trips_through_its_own_validator(primitive_id: str) -> None:
    """A descriptor that cannot re-validate itself is not a stable declaration.

    The round-trip re-runs the constructor rules, so a primitive that only
    validated because of an import-time default fails here.
    """
    primitive = descriptor_for(primitive_id)
    assert type(primitive).model_validate(primitive.model_dump()) == primitive


@pytest.mark.parametrize("primitive_id", ALL_IDS)
def test_probe_caps_never_appear_without_a_required_cap(primitive_id: str) -> None:
    """The public consequence of the cap-bit mapping rule.

    A cap-bit name the gate must evaluate always rides with an agent capability
    a handshake has to advertise, so the two can never be declared apart.
    """
    primitive = descriptor_for(primitive_id)
    if primitive.probe_caps:
        assert primitive.required_caps


def test_sys_admin_is_absent_from_the_gate_today_so_kernel_primitives_are_blocked() -> None:
    """Pins the specific gap the kernel family is waiting on."""
    assert "SYS_ADMIN" not in impact._CAP_BITS
    for primitive_id in ("kernel.syscall_errno", "kernel.syscall_latency"):
        verdict = descriptor_for(primitive_id).substrate_verdict()
        assert GapReason.CAP_BIT_UNDEFINED in {gap.reason for gap in verdict.gaps}


def test_the_domain_module_may_not_import_the_gate_it_restates() -> None:
    """Why the restatement is a copy and not an import.

    ``mayhem.domain`` is below ``mayhem.agents`` in the layered contract, so
    ``lowlevel.py`` cannot ask the real gate anything. That is why
    :data:`CURRENT_SUBSTRATE` exists and why the first four tests in this file
    are not optional.
    """
    source = Path(lowlevel_module.__file__).read_text(encoding="utf-8")
    imported: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            imported.add(node.module)
    forbidden = (
        "mayhem.toolkit",
        "mayhem.agents",
        "mayhem.controller",
        "mayhem.infra",
        "asyncio",
        "socket",
        "subprocess",
        "sqlite3",
        "os",
        "pathlib",
    )
    assert not [name for name in sorted(imported) if name.startswith(forbidden)]


# ── 5. the negative controls ────────────────────────────────────────────────


def test_a_descriptor_claiming_a_capability_no_manifest_provides_is_refused() -> None:
    """The demand is real, the mechanism is undeclared, so the claim is refused.

    ``jvm.attach`` is in no manifest's ``provides`` and ``jcmd`` is in no probe
    set. A descriptor that asks for it and then says nothing is missing is the
    exact shape of the ``ip`` bug: a fault registered as if it works, with a gate
    that can never see it.
    """
    unbacked = KernelPrimitive(
        **_minimal_kernel(
            id="kernel.unbacked",
            tool_capabilities=frozenset({"kernel.unbacked_capability"}),
        )
    )
    verdict = unbacked.substrate_verdict(CURRENT_SUBSTRATE)
    assert not verdict.injectable
    assert verdict.gaps[0].demand == "tool:kernel.unbacked_capability"
    with pytest.raises(InvariantViolationError) as refusal:
        validate_substrate_claims(unbacked, CURRENT_SUBSTRATE)
    assert refusal.value.rule == "lowlevel.undeclared_missing"
    assert "tool:kernel.unbacked_capability" in str(refusal.value)


def test_a_descriptor_with_no_reversibility_statement_is_refused() -> None:
    """Reversibility is a required object, not a flag that defaults to ``True``."""
    payload = _minimal_kernel()
    del payload["reversibility_statement"]
    with pytest.raises(ValidationError) as refusal:
        KernelPrimitive(**payload)  # type: ignore[arg-type]
    assert "reversibility_statement" in str(refusal.value)


@pytest.mark.parametrize("blank", ["", "   "])
def test_a_descriptor_whose_undo_is_blank_is_refused(blank: str) -> None:
    with pytest.raises(ValidationError) as refusal:
        ReversibilityStatement(
            reversibility=Reversibility.REVERSIBLE,
            undo=blank,
            verification="a canary call behaves as it did before",
            compensation_template="probe.undo",
        )
    assert "undo" in str(refusal.value)


def test_an_irreversible_primitive_cannot_claim_a_compensation_template() -> None:
    """There is nothing for a template to undo, so claiming one is a false promise."""
    with pytest.raises(ValidationError) as refusal:
        ReversibilityStatement(
            reversibility=Reversibility.IRREVERSIBLE,
            undo="none: the bytes are already accepted",
            verification="the divergence is reported, not repaired",
            compensation_template="storage.restore_bytes",
            reconciliation="restore from the pre-injection digest",
        )
    assert "cannot claim a compensation template" in str(refusal.value)


def test_an_irreversible_primitive_must_say_what_reconciles_it() -> None:
    with pytest.raises(ValidationError) as refusal:
        ReversibilityStatement(
            reversibility=Reversibility.IRREVERSIBLE,
            undo="none: the bytes are already accepted",
            verification="the divergence is reported, not repaired",
        )
    assert "reconciles" in str(refusal.value)


def test_a_primitive_with_no_residue_check_is_refused() -> None:
    payload = _minimal_kernel()
    del payload["residue_checks"]
    with pytest.raises(ValidationError) as refusal:
        KernelPrimitive(**payload)  # type: ignore[arg-type]
    assert "residue_checks" in str(refusal.value)


def test_an_empty_residue_check_list_is_refused() -> None:
    """``()`` is not a way to say "none needed" — it is an absent check."""
    with pytest.raises(ValidationError) as refusal:
        KernelPrimitive(**_minimal_kernel(residue_checks=()))
    assert "residue_checks" in str(refusal.value)


def test_a_primitive_that_declares_nothing_missing_while_ungated_is_refused() -> None:
    payload = _minimal_kernel(
        id="kernel.ungated",
        probe_bins=frozenset({"bpftool"}),
        required_caps=frozenset({Capability.SYS_ADMIN}),
        probe_caps=frozenset({"SYS_ADMIN"}),
    )
    undeclared = KernelPrimitive(**payload)  # type: ignore[arg-type]
    with pytest.raises(InvariantViolationError) as refusal:
        validate_substrate_claims(undeclared, CURRENT_SUBSTRATE)
    assert refusal.value.rule == "lowlevel.undeclared_missing"


def test_a_primitive_that_claims_a_working_mechanism_is_missing_is_refused() -> None:
    """The over-claiming direction: an excuse on top of a working mechanism."""
    payload = _minimal_io(
        id="io.overclaimed",
        shim="marker_files",
        missing=MissingMechanism(
            mechanism="marker_files_shim",
            needed_by="nothing; the substrate carries marker files today",
            covers_reasons=frozenset({GapReason.BIN_NOT_PROBED}),
            why_no_substitute="nothing to substitute: the mechanism already works",
        ),
    )
    with pytest.raises(ValidationError) as construction:
        IOPrimitive(**payload)  # type: ignore[arg-type]
    assert "cannot declare a missing mechanism" in str(construction.value)


def test_a_primitive_naming_an_active_fault_cannot_also_claim_a_missing_mechanism() -> None:
    """A working mechanism and an "unimplemented" excuse cannot both be true."""
    with pytest.raises(ValidationError) as construction:
        KernelPrimitive(
            **_minimal_kernel(
                id="kernel.both",
                existing_fault_id="fs.fill",
                missing=MissingMechanism(
                    mechanism="a_loader",
                    needed_by="the loader itself",
                    covers_reasons=frozenset({GapReason.BIN_NOT_PROBED}),
                    why_no_substitute="nothing else does this on the target",
                ),
            )
        )
    assert "cannot also declare one missing" in str(construction.value)


def test_a_missing_mechanism_that_covers_none_of_the_real_gaps_is_refused() -> None:
    """The declaration is present, and still wrong about which gap it closes."""
    payload = _minimal_kernel(
        id="kernel.miscovered",
        probe_bins=frozenset({"bpftool"}),
        required_caps=frozenset({Capability.SYS_ADMIN}),
        probe_caps=frozenset({"SYS_ADMIN"}),
        missing=MissingMechanism(
            mechanism="something_else_entirely",
            needed_by="a mechanism that addresses a different axis",
            covers_reasons=frozenset({GapReason.HOST_TOOL_ABSENT}),
            why_no_substitute="this covers a host-tool gap the surface never raised",
        ),
    )
    miscovered = KernelPrimitive(**payload)  # type: ignore[arg-type]
    with pytest.raises(InvariantViolationError) as refusal:
        validate_substrate_claims(miscovered, CURRENT_SUBSTRATE)
    assert refusal.value.rule == "lowlevel.uncovered_gap"


def test_a_primitive_with_a_missing_mechanism_cannot_claim_verified_unit() -> None:
    payload = _minimal_kernel(
        id="kernel.overmature",
        maturity_floor=MaturityLevel.VERIFIED_UNIT,
        missing=MissingMechanism(
            mechanism="a_loader",
            needed_by="the loader itself",
            covers_reasons=frozenset({GapReason.BIN_NOT_PROBED}),
            why_no_substitute="nothing else does this on the target",
        ),
    )
    with pytest.raises(ValidationError) as refusal:
        KernelPrimitive(**payload)  # type: ignore[arg-type]
    assert "above experimental" in str(refusal.value)


def test_a_primitive_may_not_introduce_a_category_of_its_own() -> None:
    """The import-time-``KeyError`` guard, at the level it can be caught early."""
    with pytest.raises(ValidationError) as refusal:
        KernelPrimitive(**_minimal_kernel(category=FaultCategory.K8S))
    assert "would be a new category" in str(refusal.value)


def test_a_probe_cap_without_a_declared_agent_capability_is_refused() -> None:
    """``probe_caps`` and ``required_caps`` must not be able to drift apart."""
    payload = _minimal_kernel(
        id="kernel.drifted",
        probe_caps=frozenset({"SYS_ADMIN"}),
        required_caps=frozenset(),
    )
    with pytest.raises(ValidationError) as refusal:
        KernelPrimitive(**payload)  # type: ignore[arg-type]
    assert "required_caps" in str(refusal.value)


def test_a_cap_bit_with_no_capability_mapping_is_refused() -> None:
    """An unmappable cap name is a demand the domain cannot reason about."""
    payload = _minimal_kernel(
        id="kernel.unmappable",
        probe_caps=frozenset({"BPF_PERFMON"}),
        required_caps=frozenset({Capability.SYS_ADMIN}),
    )
    with pytest.raises(ValidationError) as refusal:
        KernelPrimitive(**payload)  # type: ignore[arg-type]
    assert "must map to a declared Capability" in str(refusal.value)


# ── 6. the four families' own shape rules ───────────────────────────────────


def test_errno_mode_must_name_its_errno() -> None:
    with pytest.raises(ValidationError) as refusal:
        KernelPrimitive(**_minimal_kernel(mode="errno_return"))
    assert "must name the errno" in str(refusal.value)


def test_latency_mode_may_not_name_an_errno() -> None:
    with pytest.raises(ValidationError) as refusal:
        KernelPrimitive(**_minimal_kernel(mode="latency_delay", errno_name=ErrorCode.EIO))
    assert "returns no errno" in str(refusal.value)


def test_return_mutation_mode_must_name_a_known_mutation() -> None:
    with pytest.raises(ValidationError) as refusal:
        KernelPrimitive(
            **_minimal_kernel(mode="return_mutation", return_mutation="set_it_to_nine")
        )
    assert "return_mutation must be one of" in str(refusal.value)


def test_a_platform_scoped_attach_is_refused_on_the_process_category() -> None:
    """A cgroup attach perturbs more than one process, so ``PROCESS`` is a lie."""
    for scope in ("cgroup", "namespace", "module"):
        with pytest.raises(ValidationError) as refusal:
            KernelPrimitive(**_minimal_kernel(attachment=ReverseAttachment(scope)))
        assert "FaultCategory.NODE" in str(refusal.value)


def test_an_error_mode_must_name_its_errno() -> None:
    with pytest.raises(ValidationError) as refusal:
        IOPrimitive(**_minimal_io(mode="error"))
    assert "must name the errno" in str(refusal.value)


def test_a_relative_default_path_is_refused() -> None:
    """A relative path resolves against whatever cwd the executor runs with."""
    with pytest.raises(ValidationError) as refusal:
        IOPrimitive(**_minimal_io(default_path="tmp/mayhem"))
    assert "absolute path" in str(refusal.value)


def test_exception_injection_mode_must_name_a_throwable() -> None:
    payload = _minimal_jvm_payload()
    with pytest.raises(ValidationError) as refusal:
        JVMPrimitive(**payload)
    assert "must name the exception class" in str(refusal.value)


def test_a_non_throwable_exception_class_is_refused() -> None:
    payload = _minimal_jvm_payload(exception_class="java.lang.String")
    with pytest.raises(ValidationError) as refusal:
        JVMPrimitive(**payload)
    assert "Throwable subclass" in str(refusal.value)


def test_a_non_exception_mode_may_not_inject_an_exception() -> None:
    payload = _minimal_jvm_payload(
        mode="method_delay", exception_class="java.lang.RuntimeException"
    )
    with pytest.raises(ValidationError) as refusal:
        JVMPrimitive(**payload)
    assert "injects no exception" in str(refusal.value)


def _minimal_jvm_payload(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "id": "jvm.probe",
        "family": PrimitiveFamily.JVM,
        "title": "A probe JVM primitive",
        "summary": "A summary long enough to satisfy the descriptor contract.",
        "category": FaultCategory.PROCESS,
        "risk": RiskLevel.MEDIUM,
        "max_safe_duration_s": 60.0,
        "reversibility_statement": _reversible(),
        "residue_checks": (
            ResidueCheck(
                facet=ResidueFacet.BYTECODE,
                probe="re-dump the method with the agent removed",
                expectation="the dump matches the pre-injection record",
            ),
        ),
        "target_class": "java.util.concurrent.ThreadPoolExecutor",
        "target_method": "execute",
        "instrumentation": "jvmti_agent",
        "mode": "exception_inject",
    }
    base.update(overrides)
    return base


def test_a_zero_clock_offset_is_refused() -> None:
    """A zero offset is the inert-parameter class, so it is unrepresentable."""
    payload = _minimal_clock_payload(offset_ms=0)
    with pytest.raises(ValidationError) as refusal:
        ClockPrimitive(**payload)
    assert "injects nothing" in str(refusal.value)


def test_an_unrepresentable_slew_rate_is_refused() -> None:
    """Outside the kernel's usable range ``adjtimex`` clamps, so the fault lies."""
    payload = _minimal_clock_payload(mode="rate", rate_ppm=50_000)
    with pytest.raises(ValidationError) as refusal:
        ClockPrimitive(**payload)
    assert "slew range" in str(refusal.value)


def test_freeze_mode_changes_neither_offset_nor_rate() -> None:
    payload = _minimal_clock_payload(mode="freeze", offset_ms=1_000)
    with pytest.raises(ValidationError) as refusal:
        ClockPrimitive(**payload)
    assert "neither offset nor rate" in str(refusal.value)


def _minimal_clock_payload(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "id": "clock.probe",
        "family": PrimitiveFamily.CLOCK,
        "title": "A probe clock primitive",
        "summary": "A summary long enough to satisfy the descriptor contract.",
        "category": FaultCategory.CLOCK,
        "risk": RiskLevel.HIGH,
        "max_safe_duration_s": 60.0,
        "reversibility_statement": _reversible(),
        "residue_checks": (
            ResidueCheck(
                facet=ResidueFacet.CLOCK,
                probe="two date reads 5s apart on the host and in the target",
                expectation="both clocks advanced",
            ),
        ),
        "clock_id": "realtime",
        "mode": "offset",
    }
    base.update(overrides)
    return base


# ── 7. surfaces other than today's ──────────────────────────────────────────


def test_a_fully_provisioned_surface_makes_the_missing_primitives_injectable() -> None:
    """The predicate is a function of the surface, not a hardcoded answer.

    A reviewer can check the model by handing it a surface where the eBPF loader
    exists and seeing the verdict flip. That is what makes the *negative* answers
    worth reading: they are claims about a named surface, not a permanent state.
    """
    permissive = SubstrateSurface(
        capabilities=frozenset(Capability),
        probe_bins=frozenset({"bpftool", "jcmd", "faketime", "dmsetup", "mount"}),
        cap_bits=frozenset({"NET_ADMIN", "SYS_ADMIN", "SYS_TIME"}),
        installable_bins=frozenset({"bpftool", "jcmd", "faketime", "dmsetup", "mount"}),
        host_tools=frozenset({"k6"}),
        manifest_capabilities=frozenset(
            {
                "kernel.syscall_attach",
                "kernel.syscall_latency",
                "jvm.attach",
                "clock.intercept",
                "storage.fuse_shim",
            }
        ),
    )
    # A permissive surface means the *declarations* are now over-claimed, which
    # the cross-claim check refuses rather than silently accepting.
    kernel = descriptor_for("kernel.syscall_errno")
    assert kernel.substrate_verdict(permissive).injectable
    with pytest.raises(InvariantViolationError) as refusal:
        validate_substrate_claims(kernel, permissive)
    assert refusal.value.rule == "lowlevel.over_declared_missing"


def test_an_empty_surface_reports_every_primitive_as_blocked() -> None:
    """The degenerate case: with nothing, nothing can be injected."""
    empty = SubstrateSurface()
    for primitive in ALL_PRIMITIVES:
        verdict = primitive.substrate_verdict(empty)
        assert not verdict.injectable
        assert verdict.gaps


def test_a_gap_carries_the_mechanism_the_descriptor_blames() -> None:
    gap = CapabilityGap(
        demand="bin:bpftool",
        reason=GapReason.BIN_NOT_PROBED,
        mechanism_id="ebpf_kprobe_loader",
    )
    missing = MissingMechanism(
        mechanism="ebpf_kprobe_loader",
        needed_by="a CO-RE loader and its two gate rows",
        covers_reasons=frozenset({GapReason.BIN_NOT_PROBED}),
        why_no_substitute="nothing in mayhem hooks a syscall today",
    )
    assert missing.covers(gap)
    assert not missing.covers(
        CapabilityGap(
            demand="cap:SYS_ADMIN",
            reason=GapReason.CAP_BIT_UNDEFINED,
            mechanism_id="ebpf_kprobe_loader",
        )
    )
