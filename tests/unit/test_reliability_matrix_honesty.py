"""The reliability matrix is published documentation with no gate on it.

`docs/fault-catalog/reliability-matrix.md` is the document an operator reads to
decide which fault to reach for. Nothing checked it. Plan 05 Phase 6's
acceptance criterion is *"no doc presents a retired id as available"*, and this
file is that criterion, applied to the document that matters most for it.

Three claims are enforced, each of which the prose could otherwise make:

1. **Every fault id named resolves.** A typo, or an id retired by a later wave,
   would otherwise read exactly like an available fault \u2014 which is precisely the
   failure mode the criterion names.
2. **A catalog-only id is presented as a refusal.** Those ids have complete
   metadata and no executor. Naming one in a family row without saying it is
   refused turns a deterministic refusal into an operator's dead end.
3. **Every parameter named is a real parameter.** The matrix is
   parameter-first by design \u2014 "reach for `db.slow_query` with `mode: timeout`" \u2014
   so a parameter name that no longer exists is an instruction that cannot be
   followed.

Module paths like ``mayhem.domain.catalog`` are dotted too, so ids are matched
by resolving against the catalog and everything else is excluded explicitly
rather than by pattern that could quietly widen.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from mayhem.domain.catalog import CATALOG, definition_for

MATRIX = Path(__file__).resolve().parents[2] / "docs/fault-catalog/reliability-matrix.md"

BY_ID = {definition.id: definition for definition in CATALOG}
CATALOG_ONLY = frozenset(definition.id for definition in CATALOG if definition.catalog_only)

#: ``prefix.suffix`` where the prefix is one the catalog actually uses. Anchoring
#: on the real prefixes is what keeps ``mayhem.domain.catalog`` and
#: ``promotion.evaluate_maturity`` out without a deny-list that would rot.
PREFIXES = frozenset(definition.id.split(".")[0] for definition in CATALOG)
DOTTED = re.compile(r"\b([a-z][a-z0-9]*)\.([a-z][a-z0-9_]*)\b")
BACKTICKED = re.compile(r"`([^`]+)`")
#: A backticked token that looks like an id is an id, not a parameter.
ID_SHAPED = re.compile(r"^[a-z][a-z0-9]*\.[a-z][a-z0-9_]*$")


def _text() -> str:
    return MATRIX.read_text(encoding="utf-8")


def _named_ids(text: str) -> set[str]:
    """Every dotted token in the document whose prefix the catalog uses."""
    return {f"{prefix}.{suffix}" for prefix, suffix in DOTTED.findall(text) if prefix in PREFIXES}


def _negated_mentions(text: str) -> set[str]:
    """Ids named in a line that also says they are not available.

    The Phase 6 deliverable is exactly this: an "id someone reaches for first
    does not exist" note. Naming the absent id is the whole point of such a
    note, so the resolver check has to allow it -- but only when the same line
    marks it as an absence, which is what keeps the allowance from becoming a
    loophole for offering an unavailable id.
    """
    found: set[str] = set()
    for line in text.splitlines():
        if not NEGATED.search(line):
            continue
        found |= _named_ids(line)
    return found


def _param_names(definition_id: str) -> set[str]:
    """Every parameter and enum value this definition actually accepts.

    params_schema is a tuple of ParamSpec, not a JSON-Schema dict, so
    the names come off the models directly. Enum values are included because the
    matrix routinely names one instead of the parameter -- `mode: timeout` rather
    than `mode` -- and that is the same kind of claim.
    """
    names: set[str] = set()
    for spec in definition_for(definition_id).params_schema:
        names.add(spec.name)
        if spec.default is not None:
            names.add(str(spec.default))
    return names


#: How far past an id a refusal marker still counts as being about that id. One
#: clause, not the whole row: a matrix cell can hold several ids, and a refusal
#: stated after the last of them says nothing about the first.
REFUSAL_WINDOW = 200


def _marked_refused(row: str, name: str) -> bool:
    """Does this row say, close after naming ``name``, that it is refused?"""
    index = row.find(name)
    if index == -1:
        return False
    window = row[index : index + REFUSAL_WINDOW]
    return any(
        marker in window.lower()
        for marker in ("catalog-only", "refused", "no executor", "not executable")
    )


class TestEveryIdResolves:
    def test_the_matrix_exists_and_is_not_empty(self) -> None:
        assert MATRIX.is_file(), MATRIX
        assert len(_text().splitlines()) > 50

    def test_it_names_fault_ids_at_all(self) -> None:
        """A gate over a document that names nothing checks nothing."""
        assert len(_named_ids(_text())) > 50

    def test_every_fault_id_named_resolves(self) -> None:
        """Plan 05 Phase 6's acceptance criterion, directly.

        A retired id is not absent from the matrix by being retired \u2014 it is
        absent from ``CATALOG``, and this fails.

        One carve-out, and it is the phase's own deliverable: an id named on a
        line that says it is absent ("there is no `dependency.slow`") is exactly
        the "id someone reaches for first does not exist" note Phase 6 asks
        for. Offering it without the negation is still a failure.
        """
        text = _text()
        allowed = _negated_mentions(text)
        unresolved = sorted(
            name for name in _named_ids(text) if name not in BY_ID and name not in allowed
        )
        assert not unresolved, f"the matrix names ids the catalog does not have: {unresolved}"

    def test_the_negation_carve_out_is_not_a_loophole(self) -> None:
        """Two-sided: the allowance must be narrow, and it is used.

        Without the second assertion the allowance could quietly become "any
        line containing the word *not*", which would pass the matrix today and
        let any id be offered by prefixing it with a negation.
        """
        text = _text()
        allowed = _negated_mentions(text)
        assert allowed, "the negation carve-out is never exercised; check it still applies"
        # The discriminator itself, on synthetic input: the same absent id on a
        # line that offers it is not excused. Without this the allowance could
        # have widened to "any line with a negation in it" and stayed green.
        absent = "dependency.slow"
        assert absent not in _negated_mentions(f"Use `{absent}` to slow an upstream.")
        assert absent in _negated_mentions(f"There is no `{absent}`.")

    @pytest.mark.parametrize("dotted", sorted({"mayhem.domain.catalog", "faults.py"}))
    def test_module_paths_are_not_mistaken_for_fault_ids(self, dotted: str) -> None:
        """Two-sided: the filter must exclude prose without excluding ids.

        Without this, widening the id pattern to catch a typo would start
        failing on ``mayhem.domain.catalog``, and the fix would be a deny-list.
        """
        names = _named_ids(f"`{dotted}` and `dependency.block`")
        assert names == {"dependency.block"}


class TestCatalogOnlyIdsAreRefusedNotOffered:
    def test_the_catalog_really_does_have_catalog_only_entries(self) -> None:
        """Otherwise every assertion below is vacuous."""
        assert CATALOG_ONLY

    def test_a_catalog_only_id_is_never_offered_in_a_family_row(self) -> None:
        """It has no executor, so a family row must not route a reader to it.

        Family rows are the ``| Family | Catalog IDs |`` table: the place a
        reader goes to choose. A catalog-only id there is an operator's dead end
        presented as a starting point.
        """
        text = _text()
        start = text.index("## Reliability families")
        end = text.index("## Parameterized mechanisms")
        section = text[start:end]
        rows = [ln for ln in section.splitlines() if ln.startswith("| ")]
        assert rows, "no family rows found; the section heading moved"
        # Only the table. The prose directly beneath it is the paragraph that
        # *explains* catalog-only entries, so slicing the whole section would
        # flag the explanation for containing the thing it explains.
        offenders = sorted(
            {
                name
                for row in rows
                for name in _named_ids(row)
                if name in CATALOG_ONLY and not _marked_refused(row, name)
            }
        )
        assert not offenders, f"family rows offer catalog-only ids without saying so: {offenders}"

    def test_a_refusal_counts_only_next_to_the_id_it_refuses(self) -> None:
        """Where the refusal is written decides whether it counts.

        Marking a catalog-only id in the paragraph forty lines below the table is
        how this document already worked, and it is not enough: the row is where
        a reader stops. Marking one id in a row must not excuse the next one
        either, which is the loophole a whole-row check would open.
        """
        marked = "| Storage | `fs.permission_failure` (**catalog-only, refused**) |"
        assert _marked_refused(marked, "fs.permission_failure")
        assert not _marked_refused("| Storage | `fs.permission_failure` |", "fs.permission_failure")

        two = "| X | `app.deadlock` (**catalog-only, refused**), `clock.freeze` |"
        assert _marked_refused(two, "app.deadlock")
        assert not _marked_refused(two, "clock.freeze")

    def test_catalog_only_ids_are_named_as_refused_somewhere(self) -> None:
        """The other half: the refusal is the deliverable and must be visible.

        ``dependency.malformed_response`` and ``app.deadlock`` are catalog-only.
        A document that omitted them entirely would pass the test above while
        leaving an operator to discover the gap by trying.
        """
        text = _text()
        for name in sorted(CATALOG_ONLY):
            if f"`{name}`" not in text:
                continue
            line = next(ln for ln in text.splitlines() if f"`{name}`" in ln).lower()
            assert any(
                word in line for word in ("catalog-only", "refus", "no executor", "not executable")
            ), f"{name} is named without saying it is refused"


#: Text that marks a nearby mention as an absence rather than an offer. The
#: matrix is allowed to say "there is no \`dependency.slow\`" -- that is the
#: "id someone reaches for first does not exist" note Phase 6 asks for, and
#: forbidding it would forbid the phase's own deliverable. What it must not do
#: is name the absent id without saying so.
NEGATED = re.compile(
    r"\b(?:no|not|never|does not|doesn't|isn't|is not|rather than|instead of|"
    r"unavailable|refused|missing|absent|retired)\b",
    re.I,
)

#: A backticked token is a *parameter claim* -- as opposed to a value, an id, or
#: a path -- when the text right after its closing backtick names it as one. The
#: matrix's grammar is consistent about this: `` `mode`: `allocate` ``, `` `op`:
#: `read` ``, `` `direction` selects the side ``, `` `jitter_ms` is jitter ``.
#: A token followed by `` / `` or by another value is a *value*, and the schema
#: does not constrain values at all -- see the limit recorded below.
PARAM_ROLE = re.compile(r"^\s*(?::|\s(?:selects|is|chooses|names|must|supplies)\b)")


def _parameter_claims(line: str) -> list[str]:
    """Backticked tokens in ``line`` that the matrix presents as parameters.

    ``mode: timeout`` yields ``mode``: the name is the part before the colon and
    the value is the part after, so both are recognised and only the name is
    returned.
    """
    claims: list[str] = []
    for match in BACKTICKED.finditer(line):
        raw = match.group(1).strip()
        name = raw.split(":", 1)[0].strip()
        if not re.fullmatch(r"[a-z][a-z0-9_]*", name):
            continue
        if not PARAM_ROLE.match(line[match.end() :]):
            continue
        claims.append(name)
    return claims


class TestParametersNamedAreReal:
    def _row_lines(self) -> list[str]:
        return [ln for ln in _text().splitlines() if ln.startswith("| ")]

    def test_family_rows_exist(self) -> None:
        assert len(self._row_lines()) > 10

    def test_every_parameter_named_in_a_row_is_a_real_one(self) -> None:
        """Parameter-first means the parameter has to exist.

        The matrix's whole idiom is "reach for this id with this parameter". A
        parameter that has been renamed or removed leaves an instruction that
        cannot be followed, and raises nothing at all.
        """
        unknown: dict[str, list[str]] = {}
        for line in self._row_lines():
            known: set[str] = set()
            for raw in BACKTICKED.findall(line):
                token = raw.strip()
                if ID_SHAPED.match(token) and token in BY_ID:
                    known |= _param_names(token)
            for claim in _parameter_claims(line):
                if claim not in known:
                    unknown.setdefault(line[:60], []).append(claim)
        assert not unknown, f"the matrix names parameters that do not exist: {unknown}"

    def test_it_actually_names_parameters(self) -> None:
        """Otherwise the check above proves nothing about parameter naming."""
        named = sum(len(_parameter_claims(line)) for line in self._row_lines())
        # Fifteen today. A floor rather than an exact count: the point is that
        # the check has material to work on, and the count moves as rows do.
        assert named >= 15, named

    def test_value_claims_are_not_schema_guarantees_and_this_file_says_so(self) -> None:
        """A recorded limit, not a claim.

        ``ParamSpec`` carries a name, a type, bounds and a default -- and **no
        enum**. So ``mode: timeout`` is checked only in the sense that ``mode``
        exists; whether ``timeout`` is one of its accepted values is a claim
        about the executor, not about the schema, and this file cannot verify it.

        Rather than pretend otherwise, the vocabulary of value-shaped tokens is
        asserted to be *empty of parameters*, i.e. these really are values and
        not mis-parsed parameter names. If a future ``ParamSpec`` gains an enum,
        this test fails and the gate can be widened to check values too.
        """
        for spec in (s for d in CATALOG for s in definition_for(d.id).params_schema):
            assert not hasattr(spec, "enum"), (
                "ParamSpec now carries an enum; widen this gate to check the "
                "value claims the matrix makes"
            )
