"""Unique-prefix command resolution."""

import click
import pytest

from mayhem.cli.app import app
from mayhem.cli.experiment import experiment
from mayhem.cli.resolver import CommandResolutionError


def _ctx() -> click.Context:
    return click.Context(app)


class TestUniquePrefixes:
    def test_single_letter_resolves_unique_command(self) -> None:
        ctx = _ctx()
        assert app.get_command(ctx, "s") is app.get_command(ctx, "status")

    def test_nested_prefix(self) -> None:
        ctx = _ctx()
        exp = app.get_command(ctx, "experiment")
        assert isinstance(exp, click.Group)
        assert exp.get_command(ctx, "v") is experiment.get_command(ctx, "validate")

    def test_exact_name_always_works(self) -> None:
        ctx = _ctx()
        assert app.get_command(ctx, "janitor") is not None


class TestAmbiguity:
    def test_ambiguous_prefix_raises_typed_error_with_candidates(self) -> None:
        with pytest.raises(CommandResolutionError) as excinfo:
            app.get_command(_ctx(), "t")
        assert excinfo.value.candidates == ("toolkit", "topology")

    def test_no_match_raises_resolution_error(self) -> None:
        with pytest.raises(CommandResolutionError):
            app.get_command(_ctx(), "zzz")

    def test_empty_input_is_not_a_resolution_error(self) -> None:
        with pytest.raises(Exception):  # noqa: B017 — Click raises UsageError for missing command
            app.get_command(_ctx(), "")
