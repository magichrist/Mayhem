"""L4 Phase 3b — the honesty gate over the gate/budget binding plan.

The irony this file exists to discharge: a plan whose subject is "the attach
points were reported missing but exist" is itself a document, and would rot the
same way. So this gate reads `L4_GATE_ATTACHMENT.md` and refuses the claims most
likely to rot — including silently reverting to the *original false premise*,
that no production call site attaches a gate.

Eight checks:

* the ``Overall:`` count equals the ``DONE`` phase lines, and the phases are 1-3;
* every symbol the document cites still resolves through ``importlib`` — the
  binding machinery, the shipped witness provider, and the ports/gate/guard
  types they traffic in;
* the attach sites are **real**: ``mayhem.cli.lifecycle`` calls ``run_gate(``,
  calls ``run_budget_guard(``, and passes the result to ``engine_for(`` with
  ``gate=`` and ``budget_guard=``. This is the check that makes the Phase 3a
  correction self-enforcing: if a future lane removes the attach, both this
  document and the corrected plan-10 ledger become false and the suite says so;
* ``build_run_engine`` exists nowhere in ``src/`` — the stale factory name this
  plan's Phase 3 corrected out of the ledgers;
* both ``MAYHEM_GATE_WITNESSES`` and ``MAYHEM_BUDGET_GUARD`` appear in
  ``docs/``, and ``docs/config.md`` is among the files naming them — a binding
  nobody can read about is the Phase 2b defect returning;
* the document claims no false capability: no working incident-manager/backup/
  replication witnesses shipped, no ``unavailable_ports`` as a starting
  configuration, no run gated by default, no unremovable guard;
* the correction is recorded — the document says the earlier reading was wrong
  and the call sites exist, and the corrected plan-10 ledger names
  ``engine_for`` and states that ``build_run_engine`` exists nowhere in the
  tree, rather than silently pretending the original claim was right;
* ``tests/unit/test_binding_spec.py`` and ``tests/unit/binding_fixtures.py``
  exist, and the binding tests actually exercise the env seam.

Each checker is proven to bite against a mutated copy of the document.
"""

from __future__ import annotations

import inspect
import re
from pathlib import Path
from typing import TYPE_CHECKING, Final

if TYPE_CHECKING:
    from collections.abc import Iterator

REPO_ROOT: Final = Path(__file__).resolve().parents[2]
PLAN_PATH: Final = REPO_ROOT / "docs/v1.1.0/LAST/L4_GATE_ATTACHMENT.md"
PLAN: Final = PLAN_PATH.read_text(encoding="utf-8")
PLAN_10_PATH: Final = REPO_ROOT / "docs/v1.1.0/10_EMERGENCY_STOP_PREFLIGHT.md"
CONFIG_DOC: Final = REPO_ROOT / "docs/config.md"

PHASE_LINE: Final = re.compile(
    r"^-\s+Phase\s+(\d+)\b[^\n]*?:\s*\**\s*(DONE|PARTIAL|INCOMPLETE)\b([^\n]*)$", re.M
)
OVERALL_LINE: Final = re.compile(r"^Overall:\s*(\d+)\s+of\s+(\d+)\s+phases", re.M)

#: Citations this plan makes, as ``(module, attribute)``. Resolved through
#: ``importlib`` rather than by reading line numbers, because the Phase 3 rename
#: (`build_run_engine` -> `engine_for`) is exactly the edit that would rot a
#: line-number citation.
CITED_SYMBOLS: Final[tuple[tuple[str, str], ...]] = (
    ("mayhem.cli.execution", "GATE_WITNESSES_ENV"),
    ("mayhem.cli.execution", "BUDGET_GUARD_ENV"),
    ("mayhem.cli.execution", "gate_from_spec"),
    ("mayhem.cli.execution", "budget_guard_from_spec"),
    ("mayhem.cli.execution", "gate_for_ports"),
    ("mayhem.cli.execution", "attach_preflight_gate"),
    ("mayhem.cli.execution", "attach_resource_budget"),
    ("mayhem.cli.app", "run_gate"),
    ("mayhem.cli.app", "run_budget_guard"),
    ("mayhem.cli.services", "engine_for"),
    ("mayhem.controller.preflight_gate", "PreflightPorts"),
    ("mayhem.controller.preflight_gate", "PreflightGate"),
    ("mayhem.controller.preflight_gate", "PORT_SUBJECTS"),
    ("mayhem.infra.budget_enforcement", "RunBudgetGuard"),
    ("mayhem.cli.witnesses", "unavailable_ports"),
    ("mayhem.cli.witnesses", "empty_ports"),
    ("mayhem.cli.witnesses", "noop_budget_guard"),
)

#: The env seam, named by the constant the tests actually import.
GATE_WITNESSES_ENV_NAME: Final = "MAYHEM_GATE_WITNESSES"
BUDGET_GUARD_ENV_NAME: Final = "MAYHEM_BUDGET_GUARD"

#: The full attach call as ``lifecycle`` spells it: ``gate=gate`` precedes
#: ``budget_guard=run_budget_guard(`` inside one ``engine_for(`` call.
ENGINE_ATTACH_CALL: Final = re.compile(
    r"engine_for\([\s\S]{0,600}?\bgate=gate\b[\s\S]{0,600}?\bbudget_guard=run_budget_guard\("
)

#: Claims this plan must never make. Each is either the document's own original
#: false premise, or a capability it deliberately did not ship.
FORBIDDEN_CLAIMS: Final[tuple[str, ...]] = (
    r"working incident-?manager witness",
    r"working (?:backup|replication) (?:witness|probe)",
    r"unavailable_ports[^.\n]{0,80}(?:is|as) (?:the |a )?(?:starting|default) configuration",
    r"(?:every|any|all|each) runs? (?:is|are|will be) (?:now )?gated",
    r"(?<!not )gated by default",
    r"(?:cannot|can't) be (?:deleted|removed|unwired|detached)",
    r"\bunremovable\b",
)

#: One plausible over-claim per forbidden pattern, so each checker's *positive*
#: half is proven to bite. A checker that is only ever run against the real
#: document has never been shown to catch the thing it exists to catch.
_OVERCLAIMS: Final[dict[str, str]] = {
    FORBIDDEN_CLAIMS[
        0
    ]: "Mayhem ships a working incident-manager witness bound to the on-call rotation.",
    FORBIDDEN_CLAIMS[1]: "Mayhem ships a working backup probe that reports HEALTHY.",
    FORBIDDEN_CLAIMS[2]: "unavailable_ports is the starting configuration for a new deployment.",
    FORBIDDEN_CLAIMS[3]: "Every run is now gated by default.",
    FORBIDDEN_CLAIMS[4]: "Out of the box, all runs are gated by default.",
    FORBIDDEN_CLAIMS[5]: "The binding machinery cannot be removed once a witness is bound.",
    FORBIDDEN_CLAIMS[6]: "The guard is unremovable by design.",
}

#: A synthetic DONE ledger, used only by the "checker bites" test so that the
#: positive half is exercised even while the real document is still unmarked.
_BITE_LEDGER: Final = (
    "## STATUS\n\n"
    "- Phase 1 — pin the machinery: **DONE**\n"
    "- Phase 2 — make it reachable: **DONE**\n"
    "- Phase 3 — correct the ledgers: **DONE**\n\n"
    "Overall: 3 of 3 phases complete\n"
)


def _phases(text: str = PLAN) -> dict[int, str]:
    return {int(m.group(1)): m.group(2) for m in PHASE_LINE.finditer(text)}


def _resolve(module_name: str, attribute: str) -> object:
    import importlib

    return getattr(importlib.import_module(module_name), attribute)


# --- check 1: the ledger ----------------------------------------------------- #


def test_overall_count_equals_the_done_lines() -> None:
    overall = OVERALL_LINE.search(PLAN)
    assert overall is not None, "L4 has a phase ledger but no 'Overall:' line"
    phases = _phases()
    done = sum(1 for verdict in phases.values() if verdict == "DONE")
    assert int(overall.group(1)) == done, (
        f"L4 says {overall.group(1)} of {overall.group(2)} complete, "
        f"but marks {done} of {len(phases)} phases DONE"
    )
    assert int(overall.group(2)) == len(phases)


def test_all_three_phases_are_present_and_done() -> None:
    phases = _phases()
    assert set(phases) == {1, 2, 3}, sorted(phases)
    assert all(verdict == "DONE" for verdict in phases.values()), phases


# --- check 2: the cited symbols resolve -------------------------------------- #


def test_every_cited_symbol_still_exists() -> None:
    missing: list[str] = []
    for module_name, attribute in CITED_SYMBOLS:
        try:
            found = _resolve(module_name, attribute)
        except (ImportError, AttributeError) as exc:
            missing.append(f"{module_name}.{attribute} ({type(exc).__name__})")
            continue
        assert found is not None, f"{module_name}.{attribute} is None"
    assert missing == [], f"L4 cites symbols that no longer exist: {missing}"


# --- check 3: the attach sites are real -------------------------------------- #


def test_the_attach_sites_still_exist_in_lifecycle() -> None:
    """The Phase 3a correction says the call sites exist; they must.

    This is the check that makes the correction self-enforcing: remove the
    attach and both this document and the corrected plan-10 ledger become the
    next stale entries, and the suite says so.
    """
    from mayhem.cli import lifecycle

    source = inspect.getsource(lifecycle)
    assert "run_gate(" in source, (
        "the document says cli/lifecycle.py calls run_gate(), and it does not"
    )
    assert "run_budget_guard(" in source, (
        "the document says cli/lifecycle.py calls run_budget_guard(), and it does not"
    )


def test_engine_for_is_called_with_both_the_gate_and_the_budget_guard() -> None:
    """``engine_for(..., gate=gate, budget_guard=run_budget_guard(...))``."""
    from mayhem.cli import lifecycle

    matches = ENGINE_ATTACH_CALL.findall(inspect.getsource(lifecycle))
    assert matches, (
        "no engine_for() call in cli/lifecycle.py passes both gate= and "
        "budget_guard=; the document's attach claim is false again"
    )


# --- check 4: the stale factory name is gone --------------------------------- #


def test_build_run_engine_exists_nowhere_in_src() -> None:
    """The corrected ledgers say the old name exists nowhere; scan for it."""
    import mayhem

    # ``mayhem`` is a namespace package, so ``__file__`` is None and the
    # source root is the first (only) entry of ``__path__``.
    src_root = Path(next(iter(mayhem.__path__)))
    offenders = [
        str(path.relative_to(src_root))
        for path in src_root.rglob("*.py")
        if "build_run_engine" in path.read_text(encoding="utf-8", errors="ignore")
    ]
    assert offenders == [], f"build_run_engine is back in src/: {offenders}"


# --- check 5: the env seam is documented ------------------------------------- #


def _docs_mentioning(needle: str) -> set[Path]:
    docs_root = REPO_ROOT / "docs"
    return {
        path
        for path in docs_root.rglob("*")
        if path.is_file() and needle in path.read_text(encoding="utf-8", errors="ignore")
    }


def test_both_binding_variables_are_documented_including_config_md() -> None:
    """A binding nobody can read about is the Phase 2b defect returning."""
    for needle in (GATE_WITNESSES_ENV_NAME, BUDGET_GUARD_ENV_NAME):
        found = _docs_mentioning(needle)
        assert found, f"{needle} appears in no document under docs/"
        assert CONFIG_DOC in found, (
            f"{needle} is documented, but not in docs/config.md — the section "
            "'Bindings outside `mayhem.yaml`' is the authoritative summary"
        )


# --- check 6: what this plan may not claim ----------------------------------- #


def test_the_document_claims_no_false_capability() -> None:
    found = [pattern for pattern in FORBIDDEN_CLAIMS if re.search(pattern, PLAN, re.I)]
    assert found == [], f"L4 claims something false: {found}"


# --- check 7: the correction is recorded ------------------------------------- #


def test_the_plan_records_that_the_earlier_reading_was_wrong() -> None:
    """The document must not silently be rewritten to pretend it was right."""
    assert "That was wrong" in PLAN, (
        "L4 no longer records that the earlier reading was wrong; the "
        "correction is the finding and must stay in the ledger"
    )
    assert "The call sites exist" in PLAN, (
        "L4 no longer asserts that the attach call sites exist — that is the "
        "corrected premise the whole plan rests on"
    )


def test_the_corrected_plan_10_ledger_names_the_true_factory() -> None:
    """The stale sentence may survive only inside an explicit retraction."""
    text = PLAN_10_PATH.read_text(encoding="utf-8")
    assert "exists nowhere in the tree" in text, (
        "plan 10 no longer states that build_run_engine is gone from the tree"
    )
    stale = "No production call site attaches a gate"
    for line in text.splitlines():
        if stale in line:
            assert "previously read" in line, (
                f"plan 10 re-asserts the stale claim outside a retraction: {line[:120]!r}"
            )


# --- check 8: the binding tests exist and exercise the env seam --------------- #


def test_the_binding_tests_and_fixtures_exist() -> None:
    for name in ("test_binding_spec.py", "binding_fixtures.py"):
        assert (REPO_ROOT / "tests/unit" / name).is_file(), f"tests/unit/{name} does not exist"


def test_the_binding_tests_exercise_the_env_seam() -> None:
    """Phase 1's whole point was closing the env seam end to end."""
    source = (REPO_ROOT / "tests/unit/test_binding_spec.py").read_text(encoding="utf-8")
    assert GATE_WITNESSES_ENV_NAME in source or "GATE_WITNESSES_ENV" in source


# --- the checkers bite -------------------------------------------------------- #


def test_the_ledger_checker_bites() -> None:
    inflated = _BITE_LEDGER.replace(
        "Overall: 3 of 3 phases complete", "Overall: 2 of 3 phases complete"
    )
    match = OVERALL_LINE.search(inflated)
    assert match is not None
    phases = {int(m.group(1)): v for m in PHASE_LINE.finditer(inflated) for v in (m.group(2),)}
    done = sum(1 for v in phases.values() if v == "DONE")
    assert int(match.group(1)) != done, "ledger checker did not bite"


def test_the_forbidden_claim_checker_bites() -> None:
    for pattern in FORBIDDEN_CLAIMS:
        # Each pattern must match at least one plausible over-claim, and must not
        # match the sentence L4 actually makes. The negative half matters as much
        # as the positive: a pattern so broad it also refuses the honest wording
        # gets "fixed" by being deleted.
        assert re.search(pattern, _OVERCLAIMS[pattern], re.I), (
            f"the checker for {pattern!r} does not bite on {_OVERCLAIMS[pattern]!r}"
        )
        assert re.search(pattern, PLAN, re.I) is None


def test_the_attach_checker_bites_on_a_detached_engine_call() -> None:
    """Strip the kwargs from the call and the pattern must stop matching."""
    from mayhem.cli import lifecycle

    source = inspect.getsource(lifecycle)
    detached = re.sub(r"\s*gate=gate,\s*\n\s*budget_guard=run_budget_guard\([^)]*\),", "", source)
    assert ENGINE_ATTACH_CALL.search(source), "the fixture found no attached call"
    assert ENGINE_ATTACH_CALL.search(detached) is None, "attach checker did not bite"


def _phases_iter() -> Iterator[int]:  # pragma: no cover
    yield from sorted(_phases())
