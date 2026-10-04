"""The audit stream owns its ``KIND_*`` vocabulary, and nothing else declares one.

Plan 07 Phase 4 and plan 15 Phase 4 each declared an audit kind in their *own*
module, because ``infra/audit_stream.py`` was not theirs to edit, and each plan
recorded the deferral as an open item owed to that table's owner:

* ``KIND_POLICY_VERSION_CHANGED`` was declared in ``controller/policy_evidence.py``;
* ``KIND_RESILIENCE_BOUNDARY_SEARCHED`` was declared in
  ``controller/analytics_service.py``.

Both are now declared in ``infra/audit_stream.py``, which is where the closed
``KIND_*`` table lives. This file is the durable form of that move: a test that
still passes when a kind is re-declared in a foreign module is a comment, and the
regression this guards against is exactly the silent one — a second spelling of an
action name that the table was created to prevent.

Why the test reads source rather than only importing names
-----------------------------------------------------------

Importing :data:`~mayhem.infra.audit_stream.KIND_POLICY_VERSION_CHANGED` and
asserting its value would still pass if both modules defined it and one merely
agreed. The failure worth catching is a *second definition*, which is invisible to
any value-level assertion. So the load-bearing test here scans
``src/mayhem/**/*.py`` for assignments to the two names and requires that the
module declaring them is ``infra/audit_stream.py`` and nothing else.

One honest limitation, stated rather than papered over
------------------------------------------------------

**The table is not enforced.** :class:`~mayhem.infra.audit_stream.AuditEntry`
validates only that ``action`` is a non-blank trimmed string, and ``M0029``'s
``CHECK`` constraints admit any non-blank, delimiter-free string, so declaring a
kind here is not what makes it legal to record. That is a property of the module,
not a gap these tests paper over: this file pins *where the declarations live*,
which is the half that is otherwise unprotected. Closing the table at write time is
a separate change with its own blast radius — it would refuse
``controller/advisor_service.py``'s two kinds, which are still declared outside
this table, and every ad-hoc action string a test writes. That is reported as an
open item rather than done here.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from pathlib import Path

import pytest

from mayhem.controller import analytics_service, policy_evidence
from mayhem.domain.attestation import AttestedTimestamp
from mayhem.infra import audit_stream
from mayhem.infra.audit_stream import (
    AuditEntry,
)

#: ``src/mayhem``, resolved from this file so the scan never depends on a cwd or on
#: an installed copy of the package.
SOURCE_ROOT = Path(__file__).resolve().parents[2] / "src" / "mayhem"

#: The module that owns the closed vocabulary. Every kind below must be defined here.
OWNING_MODULE = "audit_stream.py"

#: The two kinds this work item folded in, with the values the moving plans
#: documented. The values are pinned so a "move" that silently re-spelled an
#: action — the exact harm the table exists to prevent — fails here.
FOLDED_IN: dict[str, str] = {
    "KIND_POLICY_VERSION_CHANGED": "audit.policy.version_changed",
    "KIND_RESILIENCE_BOUNDARY_SEARCHED": "audit.resilience_boundary.searched",
}

#: ``NAME: str = ...``, ``NAME = ...``, and the annotated spelling. Matched at the
#: start of a line so an import or a *use* never reads as a declaration.
_DECLARATION = re.compile(
    r"^(?P<name>KIND_[A-Z0-9_]+)\s*(?::\s*[^=]+)?=", re.MULTILINE
)


def declared_kinds() -> dict[str, list[str]]:
    """Map every ``KIND_*`` name defined in ``src/mayhem`` to the files defining it.

    Scans source text rather than importing, because a module's namespace cannot
    tell you *where* a name came from once it has been rebound.
    """
    found: dict[str, list[str]] = {}
    for path in sorted(SOURCE_ROOT.rglob("*.py")):
        source = path.read_text(encoding="utf-8")
        for match in _DECLARATION.finditer(source):
            found.setdefault(match.group("name"), []).append(path.name)
    return found


def kinds_declared_in(name: str) -> list[str]:
    """The source files that assign ``name``, sorted. Empty means nowhere."""
    return sorted(declared_kinds().get(name, ()))


# --------------------------------------------------------------------------- #
# The two kinds are in the owning table                                          #
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("name", sorted(FOLDED_IN))
def test_the_folded_in_kind_is_declared_in_the_owning_module(name: str) -> None:
    """One declaration, and it is the module that owns the table."""
    assert kinds_declared_in(name) == [OWNING_MODULE]


@pytest.mark.parametrize("name,value", sorted(FOLDED_IN.items()))
def test_the_folded_in_kind_keeps_the_string_the_moving_plan_documented(
    name: str, value: str
) -> None:
    """A move relocates a name; it must not re-spell the action an auditor filters on."""
    assert getattr(audit_stream, name) == value


@pytest.mark.parametrize("name", sorted(FOLDED_IN))
def test_the_owning_table_exports_the_folded_in_kind(name: str) -> None:
    """In ``__all__``, so it is public API and not an implementation detail."""
    assert name in audit_stream.__all__


@pytest.mark.parametrize("name", sorted(FOLDED_IN))
def test_the_folded_in_kind_still_doubles_as_the_event_kind(name: str) -> None:
    """``action`` *is* the ``event_kind``: unchanged by the consolidation.

    This is the format-stability control. The move touched declarations only, so
    the string an auditor filters the stream by must be byte-identical to before.
    """
    kind = getattr(audit_stream, name)
    built = AuditEntry(principal="ana", action=kind, target="run-1:manifest")

    event = built.to_event(
        stream_id=audit_stream.DEFAULT_STREAM_ID,
        sequence=0,
        recorded_at=AttestedTimestamp(
            wall_clock=datetime(2026, 3, 1, tzinfo=UTC),
            monotonic_ns=1,
            uncertainty_ms=0.0,
            source="system",
        ),
    )

    assert event.event_kind == kind
    assert event.payload["action"] == kind
    assert kind.startswith("audit.")


# --------------------------------------------------------------------------- #
# Existing imports keep resolving                                                #
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("module", "name"),
    [
        (policy_evidence, "KIND_POLICY_VERSION_CHANGED"),
        (analytics_service, "KIND_RESILIENCE_BOUNDARY_SEARCHED"),
    ],
    ids=["policy_evidence", "analytics_service"],
)
def test_the_old_import_path_still_resolves_to_the_owners_value(module: object, name: str) -> None:
    """Re-export, not a copy: identity equality proves there is one string object."""
    assert getattr(module, name) is getattr(audit_stream, name)


def test_the_analytics_module_still_exports_its_kind_publicly() -> None:
    """``__all__`` is part of the compatibility surface, not an internal detail."""
    assert "KIND_RESILIENCE_BOUNDARY_SEARCHED" in analytics_service.__all__


def test_the_old_import_paths_are_importable_by_name() -> None:
    """The form a caller actually writes, exercised rather than assumed.

    The local names deliberately shadow the module-level imports of the same name:
    if the re-export ever stopped resolving, this function would fail to import at
    all rather than quietly comparing an attribute to itself.
    """
    from mayhem.controller.analytics_service import KIND_RESILIENCE_BOUNDARY_SEARCHED
    from mayhem.controller.policy_evidence import KIND_POLICY_VERSION_CHANGED

    assert KIND_POLICY_VERSION_CHANGED == audit_stream.KIND_POLICY_VERSION_CHANGED
    assert KIND_RESILIENCE_BOUNDARY_SEARCHED == (
        audit_stream.KIND_RESILIENCE_BOUNDARY_SEARCHED
    )


# --------------------------------------------------------------------------- #
# The durable guard: no foreign module may redeclare one                        #
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("name", sorted(FOLDED_IN))
def test_no_foreign_module_redeclares_the_kind(name: str) -> None:
    """The regression this file exists for, stated as its own failure message.

    If someone pastes ``KIND_POLICY_VERSION_CHANGED = "audit.policy.version_changed"``
    back into a controller module — to "make it locally obvious" — this fails with
    the file to delete the line from, rather than leaving two spellings of one
    action where nothing can tell they are the same.
    """
    assert kinds_declared_in(name) == [OWNING_MODULE], (
        f"{name} is declared outside {OWNING_MODULE}. The audit stream owns the closed "
        f"KIND_* vocabulary; declare it there and import it. Found in: "
        f"{kinds_declared_in(name)}"
    )


@pytest.mark.parametrize("name", sorted(FOLDED_IN))
def test_the_folded_in_kinds_appear_in_no_other_literal_assignment(name: str) -> None:
    """The kind's *value* is spelled exactly once in the source tree."""
    literal = FOLDED_IN[name]
    assignment = re.compile(rf"^\s*{re.escape(name)}\s*(?::[^=]+)?=")
    offenders: list[str] = []
    for path in sorted(SOURCE_ROOT.rglob("*.py")):
        if path.name == OWNING_MODULE:
            continue
        for line in path.read_text(encoding="utf-8").splitlines():
            if literal in line and assignment.match(line):
                offenders.append(f"{path.name}: {line.strip()}")
    assert offenders == []


def test_the_owning_module_is_where_every_audit_kind_the_audit_stream_records_is_named() -> None:
    """The table is the owner, and the two folded-in kinds are members of it.

    Scoped to the kinds this work item folded in, on purpose: the audit stream's
    ``KIND_*`` table is *not* currently the whole set of audit kinds in the
    repository — ``controller/advisor_service.py`` declares two more
    (``KIND_ADVISORY_REPLAY_COMPILED``, ``KIND_ADVISORY_CLAIM_SEALED``) in a module
    this work item does not own. Asserting the full set here would fail on another
    agent's open item and turn this guard into noise it gets deleted to silence.
    """
    members = {
        name
        for name, files in declared_kinds().items()
        if files == [OWNING_MODULE]
    }
    assert FOLDED_IN.keys() <= members
    # And the table's pre-existing members are still exactly one declaration each.
    assert {
        "KIND_RUN_SEALED",
        "KIND_EVIDENCE_REGISTERED",
        "KIND_EVIDENCE_ARCHIVED",
        "KIND_EVIDENCE_DELETED",
        "KIND_LEGAL_HOLD_PLACED",
        "KIND_LEGAL_HOLD_RELEASED",
    } <= members


# --------------------------------------------------------------------------- #
# The table is declared, not enforced — stated so the file cannot imply otherwise #
# --------------------------------------------------------------------------- #


def test_the_table_is_not_enforced_so_this_file_does_not_claim_it_is() -> None:
    """The honesty control on the control.

    The table reads as a closed vocabulary. It is not one: nothing refuses an
    undeclared action. This asserts the *present* behaviour so the file cannot be
    read as claiming enforcement it does not have — and so if enforcement is ever
    added, this test fails and the module docstring has to be updated with it.
    """
    undeclared = AuditEntry(
        principal="ana",
        action="audit.not.in.the.table",
        target="run-1:manifest",
    )

    assert undeclared.action == "audit.not.in.the.table"
    assert undeclared.action not in set(FOLDED_IN.values())
    # Constructing it does not raise, and ``record`` is not reached here: the point
    # is that the entry type itself accepts an action outside the table, so the
    # table's authority is documentary.
    assert isinstance(undeclared, AuditEntry)


def test_source_root_is_the_repository_package() -> None:
    """A wrong root would make every scan above vacuously pass."""
    assert SOURCE_ROOT.is_dir()
    assert (SOURCE_ROOT / "infra" / "audit_stream.py").is_file()
    assert (SOURCE_ROOT / "controller" / "policy_evidence.py").is_file()
    assert (SOURCE_ROOT / "controller" / "analytics_service.py").is_file()
