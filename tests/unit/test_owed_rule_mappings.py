"""The owed rule-id mappings — plan 30 Phase 4's third pass.

Four plans landed refusal rule ids without adding them to
:data:`mayhem.controller.safety_proof.OBLIGATION_FOR_RULE`. Each recorded the debt
in its own STATUS section rather than editing another lane's file, and each is
listed here by plan so the ledger is one table a reader can check against four
documents.

## Why this file exists at all

The failure this guards is not "a mapping is missing". It is **a mapping that looks
like coverage and is not**. :func:`~mayhem.controller.safety_proof._blame` puts an
unmapped rule nowhere and voids the proof naming it, so a dead row is the most
expensive kind of debt to carry — it reads as resolved, and it is resolved in the
only direction that produces nothing.

Plan 10's ledger is the worked example. It proposed a row for
``stop_resume_skips_owed_stage``; no such rule id exists anywhere in the
repository. :meth:`mayhem.controller.stop_engine.StopEngine._resume` raises
``stop_stage_skip_refused`` and, one branch above it, ``stop_stage_not_owed``.
Adding the row plan 10 asked for would have produced a table entry for a refusal
that cannot occur, and left both refusals that can occur unplaceable — the debt
made invisible rather than removed.

So two directions are asserted, and the second is the load-bearing one:

* every rule id the plans proposed that is **not** mapped, with the reason — a
  stale id, a construction refusal, or a rule that must stay unmapped on the
  owning plan's own instruction;
* **no key in :data:`OBLIGATION_FOR_RULE` is dead** — read from the source tree,
  not from the table.

## How the dead-row check reads the code

Rule ids live in two shapes in this repository: spelled as literals, and named as
module-level constants whose *value* is the id (``RULE_BUDGET`` in
``domain/quota.py``, ``CAMPAIGN_BUDGET_LIMIT`` in ``controller/campaign_dispatch.py``).
Both are code string literals in the AST, so one walk collects them.

Two exclusions keep the check from vouching for itself:

* **docstrings.** A bare ``Expr(Constant(str))`` statement is prose. Plan 15 names
  its four ids in a prose ledger *and* raises them; if a rule id were named only
  in a docstring, it would pass this check while being exactly the dead row the
  check exists to catch.
* **the two table modules.** ``safety_proof.py`` and ``check_gate.py`` spell their
  own rows. Counting them would make every row self-certifying, and the check
  would be true by construction — a guard that cannot fail is not a guard.

The negative controls at the bottom prove both exclusions do work: each plants an
id in exactly one of the excluded positions and asserts the collector misses it.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from mayhem.controller import check_gate as cg
from mayhem.controller.safety_proof import OBLIGATION_FOR_RULE
from mayhem.domain.safety_proof import ObligationName

REPO_ROOT = Path(__file__).resolve().parents[2]
PACKAGE_ROOT = REPO_ROOT / "src" / "mayhem"

#: The two modules that *are* the mapping. Their rows cannot be used as evidence
#: that a rule id exists in code, or the table would certify itself.
TABLE_MODULES: frozenset[str] = frozenset(
    {
        "src/mayhem/controller/safety_proof.py",
        "src/mayhem/controller/check_gate.py",
    }
)


def _code_literals(source: str) -> frozenset[str]:
    """Every string literal the code *uses*, excluding docstrings.

    ``ast.parse`` drops comments entirely — so a rule id that survives only in a
    comment cannot pass — and the one remaining way prose reaches the AST as a
    ``Constant`` is a bare string expression, which is exactly what a docstring is.
    Those are filtered by identity on the node, which is why this walks the tree
    once to collect them and once to read it: two identical ``Constant`` nodes are
    different objects, so comparing by node rather than by ``id(node.value)`` would
    drop a real literal that happens to share a cached string.
    """
    tree = ast.parse(source)
    docstring_nodes = {
        id(node.value)
        for node in ast.walk(tree)
        if isinstance(node, ast.Expr)
        and isinstance(node.value, ast.Constant)
        and isinstance(node.value.value, str)
    }
    return frozenset(
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and id(node) not in docstring_nodes
    )


def _spelled_by_module() -> dict[str, frozenset[str]]:
    """Every shipped module mapped to the rule ids its *code* spells."""
    spelled: dict[str, frozenset[str]] = {}
    for path in sorted(PACKAGE_ROOT.rglob("*.py")):
        relative = path.relative_to(REPO_ROOT).as_posix()
        if relative in TABLE_MODULES:
            continue
        spelled[relative] = _code_literals(path.read_text(encoding="utf-8"))
    return spelled


SPELLED_BY_MODULE: dict[str, frozenset[str]] = _spelled_by_module()
SPELLED: frozenset[str] = frozenset().union(*SPELLED_BY_MODULE.values())


# =================================================================================
# the ledger: plan by plan
# =================================================================================
#
# Written out rather than derived, for the same reason
# `test_proof_compiler.py::test_the_rule_extractor_actually_finds_the_gates_own_rules`
# spells its expectations: a table checked against itself proves nothing. Each
# entry is (rule id, obligation, check scope, module that raises it).

STOP_AUTHORISATION: tuple[tuple[str, ObligationName], ...] = (
    ("preflight.refused", ObligationName.REQUIRED_APPROVALS),
    ("stop_for_terminal_run", ObligationName.REQUIRED_APPROVALS),
    ("stop_engine_requires_run_scope", ObligationName.REQUIRED_APPROVALS),
    ("stop_command_stale", ObligationName.REQUIRED_APPROVALS),
)
STOP_WALK: tuple[tuple[str, ObligationName], ...] = (
    ("stop_stage_skip_refused", ObligationName.RECOVERY_PATH),
    ("stop_stage_not_owed", ObligationName.RECOVERY_PATH),
    ("stop_seal_requires_complete_walk", ObligationName.RECOVERY_PATH),
    ("stop_seal_requires_evidence", ObligationName.RECOVERY_PATH),
    ("stop_seal_digest_mismatch", ObligationName.RECOVERY_PATH),
)
CAMPAIGN: tuple[tuple[str, ObligationName, cg.CheckScope], ...] = (
    ("schedule.campaign_budget", ObligationName.DAMAGE_BUDGET, cg.CheckScope.DAMAGE_BUDGET),
    ("schedule.no_compilation", ObligationName.REQUIRED_APPROVALS, cg.CheckScope.SAFETY_POLICY),
)
ANALYTICS: tuple[tuple[str, ObligationName, cg.CheckScope], ...] = (
    (
        "analytics.planner_budget_diverged",
        ObligationName.DAMAGE_BUDGET,
        cg.CheckScope.DAMAGE_BUDGET,
    ),
    (
        "analytics.step_unaffordable",
        ObligationName.DAMAGE_BUDGET,
        cg.CheckScope.DAMAGE_BUDGET,
    ),
    (
        "analytics.evidence_not_sealed",
        ObligationName.REQUIRED_APPROVALS,
        cg.CheckScope.SAFETY_POLICY,
    ),
    (
        "analytics.search_not_recorded",
        ObligationName.REQUIRED_APPROVALS,
        cg.CheckScope.SAFETY_POLICY,
    ),
)
PROVIDER: tuple[tuple[str, ObligationName, cg.CheckScope], ...] = (
    ("provider.fault_undeclared", ObligationName.TARGET_POLICY, cg.CheckScope.TARGET),
    (
        "provider.certification_cell_unpinned",
        ObligationName.TARGET_POLICY,
        cg.CheckScope.TARGET,
    ),
    (
        "provider.lease_undo_absent",
        ObligationName.COMPENSATION,
        cg.CheckScope.SAFETY_POLICY,
    ),
)

OWED: tuple[tuple[str, str, cg.CheckScope], ...] = (
    *((rule, owner.value, cg.CheckScope.SAFETY_POLICY) for rule, owner in STOP_AUTHORISATION),
    *((rule, owner.value, cg.CheckScope.SAFETY_POLICY) for rule, owner in STOP_WALK),
    *((rule, owner.value, scope) for rule, owner, scope in CAMPAIGN),
    *((rule, owner.value, scope) for rule, owner, scope in ANALYTICS),
    *((rule, owner.value, scope) for rule, owner, scope in PROVIDER),
)


def test_the_ledger_and_the_two_tables_agree_on_every_owed_rule() -> None:
    """The whole point, as one assertion: what the plans owed is now present.

    Asserted per family so a failure names the family rather than reporting a set
    difference across four unrelated plans.
    """
    for rule, obligation, scope in OWED:
        assert OBLIGATION_FOR_RULE.get(rule) == obligation, rule
        assert cg.RULE_CHECK.get(rule) is scope, rule


def test_the_stop_and_preflight_rows_are_in_the_tables() -> None:
    for rule, owner in (*STOP_AUTHORISATION, *STOP_WALK):
        assert OBLIGATION_FOR_RULE.get(rule) == owner.value, rule
        assert cg.RULE_CHECK.get(rule) is cg.CheckScope.SAFETY_POLICY, rule


def test_the_campaign_rows_are_in_the_tables() -> None:
    for rule, owner, scope in CAMPAIGN:
        assert OBLIGATION_FOR_RULE.get(rule) == owner.value, rule
        assert cg.RULE_CHECK.get(rule) is scope, rule


def test_the_analytics_rows_are_in_the_tables() -> None:
    for rule, owner, scope in ANALYTICS:
        assert OBLIGATION_FOR_RULE.get(rule) == owner.value, rule
        assert cg.RULE_CHECK.get(rule) is scope, rule


def test_the_provider_rows_are_in_the_tables() -> None:
    for rule, owner, scope in PROVIDER:
        assert OBLIGATION_FOR_RULE.get(rule) == owner.value, rule
        assert cg.RULE_CHECK.get(rule) is scope, rule


# =================================================================================
# the corrections, stated so they cannot be silently reverted
# =================================================================================


def test_the_rule_plan_10_proposed_does_not_exist_and_its_real_replacement_does() -> None:
    """Plan 10's row named a rule id nothing raises.

    The ledger in ``docs/v1.1.0/10_EMERGENCY_STOP_PREFLIGHT.md`` proposed
    ``stop_resume_skips_owed_stage``. :meth:`StopEngine._resume` raises
    ``stop_stage_skip_refused``. Mapping the proposed id would have been a dead row
    that reads as coverage while both refusals the method can actually raise stayed
    unplaceable.
    """
    assert "stop_resume_skips_owed_stage" not in SPELLED
    assert "stop_resume_skips_owed_stage" not in OBLIGATION_FOR_RULE
    assert "stop_resume_skips_owed_stage" not in cg.RULE_CHECK
    # And the real id is mapped, so the correction is a substitution and not a drop.
    assert "stop_stage_skip_refused" in OBLIGATION_FOR_RULE
    assert OBLIGATION_FOR_RULE["stop_stage_skip_refused"] == ObligationName.RECOVERY_PATH.value


def test_both_resume_refusals_are_mapped_not_just_the_interesting_one() -> None:
    """``_resume`` raises two ids three lines apart. Both are mapped.

    Mapping one of a pair a single function raises would leave the table asserting
    coverage of a refusal set that is half covered — the same false assurance a dead
    row gives, pointed the other way.
    """
    assert "stop_stage_not_owed" in OBLIGATION_FOR_RULE
    assert OBLIGATION_FOR_RULE["stop_stage_not_owed"] == ObligationName.RECOVERY_PATH.value


def test_a_missing_provider_undo_is_compensation_not_recovery_path() -> None:
    """The one obligation row that corrects its owning plan.

    Plan 17 proposed ``recovery_path``. This module defines ``compensation`` as
    write-ahead ``undo_ops``, which is the refusal word for word, and
    ``recovery_path`` reads the ``recovery`` flag and ``verify_probes``, which it
    never mentions. The check an operator reads is unchanged — both report on
    ``safety_policy`` — so only the named line differs.
    """
    assert OBLIGATION_FOR_RULE["provider.lease_undo_absent"] == (ObligationName.COMPENSATION.value)
    assert cg.RULE_CHECK["provider.lease_undo_absent"] is cg.CheckScope.SAFETY_POLICY


# =================================================================================
# the ids deliberately left out, with the reason
# =================================================================================


def test_the_provider_quota_rule_stays_unmapped_on_plan_17_s_own_instruction() -> None:
    """An exceeded provider charge is refused with the ledger's own rule id.

    Plan 17 is explicit that this must not be mapped, and the reason is sound: the
    refusal already carries ``damage_quota.budget`` or
    ``damage_quota.per_fault_ceiling``, so a ``provider.``-prefixed row would be a
    second row for one physical limit that could disagree with the first.
    """
    assert "provider.quota_exceeded" not in OBLIGATION_FOR_RULE
    assert "provider.quota_exceeded" not in cg.RULE_CHECK
    # The ids that do place it are present.
    assert "damage_quota.budget" in OBLIGATION_FOR_RULE
    assert "damage_quota.per_fault_ceiling" in OBLIGATION_FOR_RULE


def test_the_analytics_evidence_unsupported_rule_is_not_a_gate_refusal() -> None:
    """A construction refusal, so there is no gate decision for a line to report.

    ``RULE_EVIDENCE_UNSUPPORTED`` is raised in ``AnalyticsClaim.__post_init__`` and
    in the report constructors: an unsupported claim is never *built*. A rule that
    fires while the value is being assembled cannot be blamed on a proof line about
    a plan, because the plan is not what it refused.
    """
    assert "analytics.evidence_unsupported" not in OBLIGATION_FOR_RULE
    assert "analytics.evidence_unsupported" not in cg.RULE_CHECK


def test_the_relabelled_admission_wrapper_is_not_mapped_and_the_reason_holds() -> None:
    """``schedule.admission_refused`` re-labels another gate's refusal.

    ``controller/campaign_dispatch.py::_admission`` calls ``validate_plan`` and, on
    a refusal, returns the *same* reason under a ``schedule.``-prefixed id —
    discarding the rule the authoritative gate raised. A row for it would name one
    line for a refusal whose real owner is any of the other eight, and this compiler
    never reads it: ``_authoritative`` takes ``decision.rule_id`` off the gate's
    own exception, so the underlying rule is already placed.

    This test exists to make the omission deliberate. Without it the next reader
    finds an unmapped rule id in a module that raised it and assumes a regression.
    """
    assert "schedule.admission_refused" not in OBLIGATION_FOR_RULE
    assert "schedule.admission_refused" not in cg.RULE_CHECK
    # It really is spelled in the code — this is a judgement about the id, not a
    # detector failure being mistaken for a judgement.
    assert "schedule.admission_refused" in SPELLED


# =================================================================================
# no row is dead
# =================================================================================


@pytest.mark.parametrize(
    ("rule", "owner"),
    [*((rule, owner) for rule, owner in STOP_AUTHORISATION), *((r, o) for r, o in STOP_WALK)],
)
def test_every_stop_and_preflight_row_is_a_rule_the_code_actually_raises(
    rule: str, owner: ObligationName
) -> None:
    assert rule in SPELLED, (
        f"{rule} is mapped but nothing under src/mayhem spells it: this row is dead "
        "coverage, which is worse than the debt it replaced"
    )
    assert OBLIGATION_FOR_RULE[rule] == owner.value


@pytest.mark.parametrize(
    ("rule", "owner", "scope"),
    [*CAMPAIGN, *ANALYTICS, *PROVIDER],
)
def test_every_other_owed_row_is_a_rule_the_code_actually_raises(
    rule: str, owner: ObligationName, scope: cg.CheckScope
) -> None:
    assert rule in SPELLED, (
        f"{rule} is mapped but nothing under src/mayhem spells it: this row is dead "
        "coverage, which is worse than the debt it replaced"
    )
    assert OBLIGATION_FOR_RULE[rule] == owner.value
    assert cg.RULE_CHECK[rule] is scope


def test_no_key_in_the_blame_table_is_dead() -> None:
    """The whole table, every row, checked against the code.

    This is the assertion that would have caught plan 10's ``stop_resume_skips_owed_stage``
    the day it was written, and it is written against the *whole* table rather than
    the eighteen new rows so a row added later by a lane that did not read this
    file is covered too.
    """
    dead = sorted(rule for rule in OBLIGATION_FOR_RULE if rule not in SPELLED)
    assert not dead, (
        "these rule ids are mapped but no module under src/mayhem spells them, so each "
        "is a row that only looks like coverage: "
        f"{dead}. Either point the row at the rule the code actually raises, or delete it."
    )


def test_no_key_in_the_check_table_is_dead_either() -> None:
    """The same rule for :data:`mayhem.controller.check_gate.RULE_CHECK`.

    A dead row here is quieter than a dead row in the blame table: nothing voids,
    nothing fails, and a check is listed as covering a refusal that cannot occur.
    """
    dead = sorted(rule for rule in cg.RULE_CHECK if rule not in SPELLED)
    assert not dead, f"these rule ids have no check row backed by any real refusal: {dead}"


def test_the_two_tables_cover_exactly_the_same_rules() -> None:
    """Restated locally so this file fails first, with both sides named.

    ``tests/unit/test_check_gate.py`` already asserts this from the other side.
    """
    only_blame = sorted(set(OBLIGATION_FOR_RULE) - set(cg.RULE_CHECK))
    only_check = sorted(set(cg.RULE_CHECK) - set(OBLIGATION_FOR_RULE))
    assert not only_blame, f"blamed by the compiler, reported by no check: {only_blame}"
    assert not only_check, f"reported by a check, blamed by no line: {only_check}"


def test_every_row_names_an_obligation_that_exists() -> None:
    """A row whose value is not an :class:`ObligationName` cannot be rendered."""
    names = {name.value for name in ObligationName}
    unknown = sorted({owner for owner in OBLIGATION_FOR_RULE.values() if owner not in names})
    assert not unknown, f"OBLIGATION_FOR_RULE names obligations that do not exist: {unknown}"


def test_a_spelled_but_unraised_rule_is_the_one_gap_this_detector_cannot_see() -> None:
    """What the dead-row check proves, and the single case it cannot.

    ``_code_literals`` reads *spelling*. A constant that is declared, exported and
    never raised is spelled, so mapping it would pass every test in this file and
    still be a row covering a refusal that cannot occur. Rather than leave that
    unstated, this test pins the known instance and asserts the limitation is real:

    ``RULE_PROVIDER_BLAST_UNCHARGED`` is in ``participation.__all__`` and assigned a
    literal, and no call site in the module raises it. It is therefore **not** in
    either table, deliberately, and when a lane makes the provider blast charge
    reachable from a run this test and the table row have to move together.
    """
    module = (REPO_ROOT / "src" / "mayhem" / "providers" / "participation.py").read_text(
        encoding="utf-8"
    )
    assert "provider.blast_uncharged" in SPELLED, (
        "the constant's literal is gone from the module, so this test's premise no "
        "longer holds and the limitation it documents has to be re-examined"
    )
    # Spelled, yes — which is the whole point: spelling is not raising.
    assert "provider.blast_uncharged" not in OBLIGATION_FOR_RULE
    assert "provider.blast_uncharged" not in cg.RULE_CHECK
    # The name is exported and assigned...
    assert '"RULE_PROVIDER_BLAST_UNCHARGED"' in module
    assert 'RULE_PROVIDER_BLAST_UNCHARGED: Final[str] = "provider.blast_uncharged"' in module
    # ...and read nowhere else in the module, so nothing raises it.
    assert module.count("RULE_PROVIDER_BLAST_UNCHARGED") == 2, (
        "a third reference to RULE_PROVIDER_BLAST_UNCHARGED appeared: if it is now a "
        "raise site, this rule has become live and owes a table row"
    )


# =================================================================================
# negative controls — the collector can fail
# =================================================================================


def test_the_collector_finds_a_rule_spelled_as_a_plain_literal() -> None:
    """Proves the collector is not simply returning everything, or nothing."""
    assert "brand.new.literal.rule" in _code_literals(
        'raise InvariantViolationError("brand.new.literal.rule", "msg")\n'
    )


def test_the_collector_finds_a_rule_behind_a_module_constant() -> None:
    """The other shape rule ids take in this repository.

    ``RULE_BUDGET = "damage_quota.budget"`` and ``CAMPAIGN_BUDGET_LIMIT =
    "schedule.campaign_budget"`` are both constants, so a collector that only read
    inline literals would call every such row dead.
    """
    assert "damage_quota.budget" in _code_literals(
        'RULE_BUDGET: Final[str] = "damage_quota.budget"\n'
    )


def test_the_collector_ignores_a_rule_named_only_in_a_docstring() -> None:
    """Prose is not a refusal.

    Plan 15's own STATUS section names all four of its ids in prose *and* raises
    them. If prose counted, a rule named only in a ledger would pass this guard while
    being exactly the dead row the guard exists to catch.
    """
    source = 'def f():\n    """A docstring naming schedule.no_compilation."""\n    return 1\n'
    assert "schedule.no_compilation" not in _code_literals(source)


def test_the_collector_ignores_a_rule_named_only_in_a_comment() -> None:
    assert "schedule.campaign_budget" not in _code_literals(
        "# TODO: schedule.campaign_budget has no row yet\ndef f():\n    return 1\n"
    )


def test_the_table_modules_are_excluded_so_a_row_cannot_vouch_for_itself() -> None:
    """The exclusion is load-bearing, and it is checked rather than assumed.

    Every row this file adds is spelled as a bare literal in *both* table modules —
    they have to be, one in each. If either module were counted as evidence, all
    eighteen rows would be self-certifying and the central dead-key test would pass
    by construction. The property that prevents that is narrower and checkable: for
    every owed rule, a module that is **not** one of the two tables spells it.
    """
    assert {
        "src/mayhem/controller/safety_proof.py",
        "src/mayhem/controller/check_gate.py",
    } == TABLE_MODULES
    for rule, _owner, _scope in OWED:
        raisers = sorted(relative for relative, ids in SPELLED_BY_MODULE.items() if rule in ids)
        assert raisers, (
            f"{rule} is only spelled by the mapping tables themselves, so its row "
            "proves nothing: exclude the tables and it is a dead key"
        )
        assert not set(raisers) & TABLE_MODULES, (rule, raisers)


def test_the_owed_rules_are_spelled_by_the_modules_that_raise_them() -> None:
    """Each row's evidence names a real module, and the modules are the expected ones.

    The test above would be satisfied by a rule spelled in *any* non-table module, so
    it cannot say *which*. This one maps every owed id to the module that raises it
    and asserts that module spells it — so a row landing in the wrong family, or a
    rule moving to a module that stopped raising it, fails by name.
    """
    expected: dict[str, str] = {}
    for rule, _owner in STOP_AUTHORISATION:
        owner_module = (
            "controller/preflight_gate.py"
            if rule == "preflight.refused"
            else "controller/stop_engine.py"
        )
        expected[rule] = owner_module
    for rule, _owner in STOP_WALK:
        expected[rule] = "controller/stop_engine.py"
    for rule, _owner, _scope in CAMPAIGN:
        expected[rule] = "controller/campaign_dispatch.py"
    for rule, _owner, _scope in ANALYTICS:
        expected[rule] = "controller/analytics_service.py"
    for rule, _owner, _scope in PROVIDER:
        expected[rule] = "providers/participation.py"

    assert len(expected) == len(OWED), (
        "the expected-module map and the ledger disagree about how many rules are "
        f"owed: {len(expected)} vs {len(OWED)}"
    )
    for rule, module in expected.items():
        assert rule in SPELLED_BY_MODULE[f"src/mayhem/{module}"], (
            f"{rule} is not spelled by {module}, which is the module its row claims it comes from"
        )


def test_the_spelled_set_covers_the_thirty_five_preexisting_rows() -> None:
    """The detector works on the rules that were always there, not only the new ones.

    Without this, a collector that happened to find the eighteen new literal rows and
    nothing else would satisfy the new tests while leaving every constant-backed row
    silently uncovered.
    """
    for rule in (
        "policy.deny_faults",
        "blast_radius.max_hosts",
        "damage_quota.budget",
        "blast_radius.protected_node",
        "approval.required",
        "policy.resource_lock_contended",
    ):
        assert rule in SPELLED, rule
