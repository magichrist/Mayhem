"""Plan 22 Phase 3 — an empty cell renders as untested, never as passing.

The acceptance criterion is structural, and this file holds it to that standard:
the rule is not "the renderer was careful" but **there is no code path in which a
missing cell is skipped**, because `coverage_matrix` materialises the declared
service x fault cross product and looks states up in it.

The three properties under test, each with its own failure mode:

1. **Absence is visible.** A cell nobody has run appears, is ``absent``, renders
   as ``·``, and never contributes to the numerator.
2. **A state without a run is not a state.** A cell claiming ``PASSED`` with no
   ``last_run`` renders untested and says so, rather than inflating coverage.
3. **The denominator travels with the number.** Blocked cells are excluded --
   otherwise an operator could raise their coverage by configuring less -- and
   every rendering of a percentage prints the population it divides by.
"""

from __future__ import annotations

import json

import pytest

from mayhem.cli.coverage_map import (
    CoverageMatrix,
    MatrixCell,
    coverage_matrix,
    render_coverage_matrix,
)
from mayhem.domain.coverage import CellState, ResilienceCell

SERVICES = ("api", "web")
FAULTS = ("net.latency", "proc.pause")


def _cell(service: str, fault: str, state: CellState, last_run: str = "run-1") -> ResilienceCell:
    return ResilienceCell(
        target=service,
        service=service,
        fault=fault,
        state=state,
        last_run=last_run,
    )


def _grid(cells: tuple[ResilienceCell, ...]) -> CoverageMatrix:
    return coverage_matrix(cells, services=SERVICES, faults=FAULTS)


def _at(matrix: CoverageMatrix, service: str, fault: str) -> MatrixCell:
    for cell in matrix.flat:
        if cell.service == service and cell.fault == fault:
            return cell
    raise AssertionError(f"{service}/{fault} is not in the grid at all")


class TestAbsenceIsVisible:
    def test_the_grid_materialises_the_full_cross_product(self) -> None:
        matrix = _grid(())
        assert matrix.services == SERVICES
        assert matrix.faults == FAULTS
        assert len(matrix.flat) == 4
        assert matrix.declared == 4

    def test_an_empty_grid_is_all_absent_and_covers_nothing(self) -> None:
        matrix = _grid(())
        assert len(matrix.absent) == 4
        assert matrix.numerator == 0
        assert matrix.percent == 0.0

    def test_a_missing_cell_is_never_counted_as_passed(self) -> None:
        """The acceptance criterion, stated as a property rather than a pixel.

        Filling three of four cells must leave the fourth absent and out of the
        numerator, not silently folded into a 75%.
        """
        matrix = _grid(
            tuple(
                _cell(service, fault, CellState.PASSED)
                for service in SERVICES
                for fault in FAULTS
                if (service, fault) != ("web", "net.latency")
            )
        )
        missing = _at(matrix, "web", "net.latency")
        assert missing.absent is True
        assert missing.state is CellState.UNKNOWN
        assert missing.covered is False
        assert matrix.numerator == 3
        assert matrix.denominator == 4
        assert matrix.percent == 75.0

    def test_a_cell_would_not_be_covered_even_if_it_claimed_to_be(self) -> None:
        """The stronger form, and the one a simplified ``covered`` would fail.

        ``covered`` reads a cell's *state*, and an absent cell's state is
        ``UNKNOWN`` -- so a ``covered`` that dropped its ``counted`` and
        ``unevidenced`` terms would still pass the test above by coincidence.
        This removes the coincidence: give the position a passing claim with no
        run behind it and it must still not count, which is what "no cell
        without evidence is covered" means when there is no evidence at all.
        """
        claiming = ResilienceCell(
            target="web",
            service="web",
            fault="net.latency",
            state=CellState.PASSED,
            last_run="",
        )
        entry = _at(_grid((claiming,)), "web", "net.latency")
        assert entry.absent is False  # it does exist, it just has no evidence
        assert entry.state is CellState.UNKNOWN
        assert entry.covered is False
        assert _grid((claiming,)).percent == 0.0

    def test_an_absent_cell_renders_as_the_untested_character(self) -> None:
        rendered = render_coverage_matrix(_grid((_cell("api", "proc.pause", CellState.PASSED),)))
        row = next(ln for ln in rendered.splitlines() if ln.strip().startswith("web"))
        assert "\u00b7" in row
        assert "\u2588" not in row

    def test_the_json_carries_absent_rather_than_omitting_it(self) -> None:
        payload = json.loads(render_coverage_matrix(_grid(()), as_json=True))
        assert len(payload["rows"]) == 2
        assert all(entry["absent"] for row in payload["rows"] for entry in row)
        assert payload["summary"]["never_run"] == 4

    def test_a_never_run_cell_says_so_distinctly_from_an_unknown_one(self) -> None:
        """ "Nobody has looked" and "we looked and do not know" are different facts."""
        matrix = _grid((_cell("api", "proc.pause", CellState.INCONCLUSIVE),))
        assert _at(matrix, "web", "proc.pause").note == "never run"
        assert _at(matrix, "api", "proc.pause").note == ""


class TestAStateWithoutARunIsNotAState:
    def test_a_passing_cell_with_no_run_renders_untested(self) -> None:
        cell = _cell("api", "proc.pause", CellState.PASSED, last_run="")
        entry = _at(_grid((cell,)), "api", "proc.pause")
        assert entry.state is CellState.UNKNOWN
        assert entry.unevidenced is True
        assert entry.covered is False

    def test_and_the_discrepancy_is_shown_rather_than_hidden(self) -> None:
        cell = _cell("api", "proc.pause", CellState.PASSED, last_run="")
        rendered = render_coverage_matrix(_grid((cell,)))
        assert "no run behind it" in rendered
        assert "api/proc.pause" in rendered

    def test_it_cannot_move_the_coverage_number(self) -> None:
        matrix = _grid(
            (
                _cell("api", "proc.pause", CellState.PASSED, last_run=""),
                _cell("api", "net.latency", CellState.PASSED, last_run="run-9"),
            )
        )
        assert matrix.numerator == 1
        assert matrix.denominator == 4
        assert matrix.percent == 25.0

    @pytest.mark.parametrize(
        "state",
        [CellState.PLANNED, CellState.SKIPPED, CellState.BLOCKED, CellState.INCONCLUSIVE],
    )
    def test_states_that_never_executed_are_not_demoted(self, state: CellState) -> None:
        """A refusal is not a missing run.

        ``PLANNED`` and ``SKIPPED`` are true precisely because nothing ran, and
        flattening them to "untested" would erase the distinction a reviewer
        needs. Only states that assert an execution outcome are held to needing
        a run behind them.
        """
        entry = _at(_grid((_cell("api", "proc.pause", state, last_run=""),)), "api", "proc.pause")
        assert entry.state is state
        assert entry.unevidenced is False

    def test_the_json_agrees_with_the_human_rendering(self) -> None:
        """One rule, two renderers: they must not be able to disagree."""
        cell = _cell("api", "proc.pause", CellState.PASSED, last_run="")
        matrix = _grid((cell,))
        payload = json.loads(render_coverage_matrix(matrix, as_json=True))
        rendered = render_coverage_matrix(matrix)
        # Look the entry up by identity rather than by index: the columns are
        # sorted, so position 0 is not the cell this test is about.
        entry = next(
            item
            for row in payload["rows"]
            for item in row
            if (item["service"], item["fault"]) == ("api", "proc.pause")
        )
        assert entry["unevidenced"] is True
        assert entry["covered"] is False
        assert "no run behind it" in rendered
        assert _at(matrix, "api", "proc.pause").covered is False


class TestTheDenominatorTravelsWithTheNumber:
    def test_blocked_cells_are_excluded_from_the_denominator(self) -> None:
        """Otherwise coverage improves by configuring less."""
        matrix = _grid(
            (
                _cell("api", "proc.pause", CellState.PASSED),
                _cell("api", "net.latency", CellState.PASSED),
                _cell("web", "proc.pause", CellState.PASSED),
                _cell("web", "net.latency", CellState.BLOCKED),
            )
        )
        assert matrix.denominator == 3
        assert matrix.numerator == 3
        assert matrix.percent == 100.0
        assert matrix.declared == 4

    def test_a_blocked_cell_says_why_or_says_it_is_excluded(self) -> None:
        matrix = _grid((_cell("api", "proc.pause", CellState.BLOCKED),))
        assert "excluded from the denominator" in _at(matrix, "api", "proc.pause").note

    def test_a_blocked_cell_with_a_rationale_quotes_it(self) -> None:
        cell = ResilienceCell(
            target="api",
            service="api",
            fault="proc.pause",
            state=CellState.BLOCKED,
            next_rationale="no CAP_SYS_ADMIN on this host",
        )
        assert _at(_grid((cell,)), "api", "proc.pause").note == "no CAP_SYS_ADMIN on this host"

    def test_an_absent_cell_is_counted_because_it_is_a_real_gap(self) -> None:
        """The opposite rule from blocked, and it has to be the opposite.

        A never-run cell is exactly the thing the map exists to surface, so it
        belongs in the denominator. Excluding it would let an untested service
        report 100%.
        """
        matrix = _grid((_cell("api", "proc.pause", CellState.PASSED),))
        assert matrix.denominator == 4

    def test_the_description_quotes_the_population(self) -> None:
        description = _grid(
            (
                _cell("api", "net.latency", CellState.PASSED),
                _cell("api", "proc.pause", CellState.BLOCKED),
            )
        ).denominator_description()
        assert "1 covered of 3 testable cells" in description
        assert "4 declared" in description
        assert "2 never run" in description

    def test_every_rendering_of_a_percentage_prints_the_denominator(self) -> None:
        """Phase 6's criterion, enforced structurally rather than by prose."""
        matrix = _grid((_cell("api", "proc.pause", CellState.PASSED),))
        assert matrix.denominator_description() in render_coverage_matrix(matrix)
        payload = json.loads(render_coverage_matrix(matrix, as_json=True))
        summary = payload["summary"]
        assert summary["denominator_description"] == matrix.denominator_description()
        # The reported population must be the testable one, not the declared
        # one. With no blocked cell the two coincide, which is exactly why this
        # needs a grid that has one.
        blocked = _grid(
            (
                _cell("api", "net.latency", CellState.PASSED),
                _cell("api", "proc.pause", CellState.BLOCKED),
            )
        )
        summary = json.loads(render_coverage_matrix(blocked, as_json=True))["summary"]
        assert summary["denominator"] == 3
        assert summary["declared"] == 4
        # The reported ratio must be the one the reported population produces,
        # or the number on screen and the sentence under it describe two
        # different grids.
        assert summary["coverage_pct"] == round(
            summary["numerator"] / summary["denominator"] * 100.0, 1
        )
        assert summary["denominator"] + summary["by_state"]["blocked"] == summary["declared"]

    def test_an_empty_declaration_still_states_the_denominator(self) -> None:
        """A zero-percentage screen is exactly where a missing denominator hides."""
        rendered = render_coverage_matrix(coverage_matrix((), services=(), faults=()))
        assert "testable cells" in rendered
        assert "0 covered of 0" in rendered


class TestTheGridIsBuiltFromTheDeclaration:
    def test_omitting_the_declaration_falls_back_to_what_is_observed(self) -> None:
        """The weaker question is still answerable, and is not pretended to be more."""
        matrix = coverage_matrix((_cell("api", "proc.pause", CellState.PASSED),))
        assert matrix.services == ("api",)
        assert matrix.faults == ("proc.pause",)
        assert matrix.declared == 1

    def test_a_service_with_no_cells_still_gets_a_row(self) -> None:
        matrix = _grid((_cell("api", "proc.pause", CellState.PASSED),))
        assert "web" in matrix.services
        assert len(matrix.cells) == 2

    def test_rows_and_columns_line_up(self) -> None:
        matrix = _grid((_cell("api", "proc.pause", CellState.PASSED),))
        assert len(matrix.cells) == len(matrix.services)
        assert all(len(row) == len(matrix.faults) for row in matrix.cells)

    def test_states_are_reconcilable_against_the_grid(self) -> None:
        matrix = _grid(
            (
                _cell("api", "proc.pause", CellState.PASSED),
                _cell("api", "net.latency", CellState.BLOCKED),
            )
        )
        assert sum(matrix.by_state.values()) == matrix.declared
