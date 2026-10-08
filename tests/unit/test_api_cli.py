"""The ``mayhem api`` operator surface (plan 08, Phase 3, Phase 5).

Invoked **directly** through :class:`~click.testing.CliRunner` as
``tests/unit/test_stop_surface.py`` and ``tests/unit/test_boundary_report_surface.py``
invoke theirs, because ``cli/command_registry.py`` is not this work item's to edit.
Registration is reported as an integration dependency rather than done here.

What this file asserts, and why the invocation style matters:

* **the route table is read, not restated.** ``mayhem api routes`` prints
  :data:`mayhem.controller.api_service.ROUTES`, so a route added to the table
  appears and one removed disappears. Asserting the printed table equals the
  module's tuple is what makes the command incapable of documenting an endpoint
  that is not served;
* **the reference is generated.** ``mayhem api openapi`` writes the same document
  :func:`~mayhem.controller.api_service.openapi_document` produces, and the file it
  writes parses back to the same object — so a pinned copy in a repository cannot
  drift from the code without the test noticing;
* **the parameter table is the catalog's**, read through
  :func:`~mayhem.controller.api_service.parameter_controls`;
* **the UI renderer refuses**, and its exit code is the usage code rather than a
  success with an empty page;
* **nothing here mutates.** Every subcommand is a read or a renderer, which is
  asserted by there being no mutating command in the group at all.

Negative controls
-----------------

Four: an unknown page id, a payload that is not JSON, an empty payload, and a
payload missing the key its page is about — each asserting a *named* refusal and a
non-zero exit, plus the counter-case that a well-formed payload succeeds, so the
refusals are not a renderer that fails everything.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

import pytest
from click.testing import CliRunner

from mayhem.cli import api_cmd
from mayhem.cli.api_cmd import api
from mayhem.cli.errors import MayhemCliError
from mayhem.cli.exit_codes import ExitCode
from mayhem.controller.api_service import (
    MAX_PAGE_SIZE,
    ROUTES,
    UNIMPLEMENTED_API_SURFACES,
    openapi_document,
    parameter_controls,
)
from mayhem.controller.api_ui import PageId, ui_pages

if TYPE_CHECKING:
    from pathlib import Path

DASHBOARD_PAYLOAD: dict[str, Any] = {
    "numbers": [
        {
            "metric": "runs_failed",
            "value": 1.0,
            "unit": "runs",
            "detail": "1 of 4 linked runs failed",
            "evidence": [{"kind": "evidence_ref", "key": "ev-1", "detail": "sealed"}],
        }
    ],
    "absent_metrics": ["coverage"],
    "unlinked_runs": [],
}


def _invoke(*args: str, stdin: str | None = None) -> Any:
    """Invoke the group directly, as an unregistered command is invoked.

    The group carries no ``MayhemCliError`` handler of its own — ``cli/app.py``
    owns that, and this work item does not own ``app.py``. So a refusal surfaces
    as the typed exception rather than as an exit code here, and :func:`_refusal`
    reads it. Asserting the exception's *type* and *rule* is the stronger claim
    anyway: an exit code can be produced by an unrelated path.
    """
    return CliRunner().invoke(api, list(args), input=stdin)


def _refusal(result: Any) -> str:
    """The message of the :class:`MayhemCliError` an invocation refused with."""
    import click

    if isinstance(result.exception, click.ClickException):
        return str(result.exception)
    assert isinstance(result.exception, MayhemCliError), result.exception
    return result.exception.message


# ── the group ───────────────────────────────────────────────────────────────


def test_the_group_is_one_group_of_read_only_commands() -> None:
    import click

    assert isinstance(api, click.Group)
    assert sorted(api.commands) == ["openapi", "pages", "parameters", "routes", "ui"]


def test_every_command_is_read_only() -> None:
    """Nothing in this surface mutates, and that is checkable from the tree.

    A ``mayhem api`` that grew a write would need a plan and a gateway, and would
    need to be gated by an approval the CLI does not have. Asserted over the group
    rather than documented.
    """
    import click

    from mayhem.cli.command_registry import COMMAND_SPECS

    for name, command in api.commands.items():
        assert isinstance(command, click.Command), name
        # No sub-commands and no ``--execute``: a surface whose only options are
        # presentation flags cannot be turned into a mutation by an option.
        assert not isinstance(command, click.Group), name
        presentation = {
            "--json",
            "--out",
            "--fault",
            "--payload",
            "--api-path",
            "--html",
        }
        options = {
            token
            for param in command.params
            for token in (*param.opts, *param.secondary_opts)
            if token.startswith("--")
        }
        assert options <= presentation, (
            f"{name} declares {sorted(options - presentation)}, which is not a presentation flag"
        )
    # The registration this file once refused has landed: `api` is registered on
    # the live tree (and in COMMAND_SPECS), so the group is now reachable through
    # the resolver and the read-only sweep above runs against the real commands.
    assert "api" in {spec.name for spec in COMMAND_SPECS}


def test_help_names_the_four_questions_it_answers() -> None:
    output = _invoke("--help").output
    for command in ("routes", "openapi", "parameters", "pages", "ui"):
        assert command in output


# ── routes ──────────────────────────────────────────────────────────────────


class TestRoutes:
    def test_it_prints_the_table_it_reads(self) -> None:
        result = _invoke("routes", "--json")
        assert result.exit_code == 0
        payload = json.loads(result.output)
        assert payload["count"] == len(ROUTES)
        assert {entry["method"] for entry in payload["routes"]} == {
            route.method for route in ROUTES
        }

    def test_the_json_and_text_forms_agree_on_the_count(self) -> None:
        as_text = _invoke("routes").output
        assert f"{len(ROUTES)} endpoint(s)" in as_text
        for route in ROUTES:
            assert route.path in as_text

    def test_it_names_the_role_each_endpoint_requires(self) -> None:
        payload = json.loads(_invoke("routes", "--json").output)
        by_path = {entry["path"]: entry for entry in payload["routes"]}
        assert by_path["/api/v1/runs/{run_id}/stop"]["required_role"] == "emergency_stop"
        assert by_path["/api/v1/plans"]["required_role"] == "plan"

    def test_it_names_the_cli_command_each_mutation_is_the_face_of(self) -> None:
        payload = json.loads(_invoke("routes", "--json").output)
        mutations = [entry for entry in payload["routes"] if entry["mutating"]]
        assert mutations, "the route table has mutations"
        for entry in mutations:
            assert entry["command_path"], entry["path"]
            assert entry["idempotent"] is True

    def test_it_prints_what_this_build_does_not_serve(self) -> None:
        output = _invoke("routes").output
        for surface in UNIMPLEMENTED_API_SURFACES:
            assert surface in output, surface

    def test_the_pagination_maximum_is_published(self) -> None:
        document = openapi_document()
        limit = document["components"]["parameters"]["limit"]["schema"]
        assert limit["maximum"] == MAX_PAGE_SIZE


# ── openapi ─────────────────────────────────────────────────────────────────


class TestOpenapi:
    def test_it_prints_the_generated_document(self) -> None:
        result = _invoke("openapi")
        assert result.exit_code == 0
        assert json.loads(result.output) == openapi_document()

    def test_it_writes_a_file_that_parses_back_to_the_same_object(self, tmp_path: Path) -> None:
        out = tmp_path / "openapi.json"
        result = _invoke("openapi", "--out", str(out))
        assert result.exit_code == 0
        assert out.exists()
        assert json.loads(out.read_text(encoding="utf-8")) == openapi_document()

    def test_every_route_is_documented(self) -> None:
        document = json.loads(_invoke("openapi").output)
        documented = {
            (method, path) for path, entry in document["paths"].items() for method in entry
        }
        assert documented == {(route.method.lower(), route.path) for route in ROUTES}


# ── parameters ──────────────────────────────────────────────────────────────


class TestParameters:
    def test_it_reads_the_catalog(self) -> None:
        payload = json.loads(_invoke("parameters", "--json").output)
        expected = parameter_controls()
        assert payload["count"] == len(expected)
        assert payload["parameters"] == [row.to_payload() for row in expected]

    def test_a_fault_filter_narrows_the_table(self) -> None:
        payload = json.loads(_invoke("parameters", "--fault", "mem.leak", "--json").output)
        assert {row["fault_id"] for row in payload["parameters"]} == {"mem.leak"}
        assert payload["count"] < len(parameter_controls())

    def test_an_unknown_fault_reads_as_empty_not_as_an_error(self) -> None:
        """A catalog lookup with no match is a fact, not a crash.

        The CLI's own fault-lookup convention is to raise for an unknown id, but a
        *filter* on a list is not a lookup: "this fault declares no parameters" is
        the answer, and an exit code for it would make a UI's empty control table
        look like a failure.
        """
        result = _invoke("parameters", "--fault", "no.such.fault")
        assert result.exit_code == 0
        assert "no catalog parameter" in result.output

    def test_the_text_form_shows_the_widget_and_the_risk(self) -> None:
        output = _invoke("parameters", "--fault", "mem.leak").output
        assert "mem.leak" in output
        assert "slider" in output
        assert "risk=" in output

    def test_the_widgets_the_ui_renders_are_the_widgets_this_prints(self) -> None:
        """One schema, one interpretation, in both surfaces.

        ``_widget`` reads ``kind`` off the same payload this command prints, so a
        control kind cannot be right in the browser and wrong on the terminal.
        """
        printed = {
            (row["fault_id"], row["name"]): row["kind"]
            for row in json.loads(_invoke("parameters", "--json").output)["parameters"]
        }
        projected = {(row.fault_id, row.name): row.kind.value for row in parameter_controls()}
        assert printed == projected


# ── pages ───────────────────────────────────────────────────────────────────


def test_pages_lists_every_page_the_renderer_knows() -> None:
    output = _invoke("pages").output
    for entry in ui_pages():
        assert entry["page"] in output


def test_ui_without_a_page_name_lists_them() -> None:
    output = _invoke("ui").output
    for entry in PageId:
        assert entry.value in output


# ── ui: the four negative controls, and the counter-case ────────────────────


class TestTheUiRenderer:
    def test_a_well_formed_payload_renders(self) -> None:
        result = _invoke("ui", "dashboard", stdin=json.dumps(DASHBOARD_PAYLOAD))
        assert result.exit_code == 0
        assert "runs_failed" in result.output

    def test_an_unknown_page_is_refused_with_the_usage_code(self) -> None:
        result = _invoke("ui", "no-such-page", stdin=json.dumps({}))
        assert result.exit_code != 0
        assert result.exception.code == "usage_error"
        assert result.exception.exit_code is ExitCode.USAGE_ERROR
        assert "no UI page" in _refusal(result)

    def test_a_payload_that_is_not_json_is_refused(self) -> None:
        result = _invoke("ui", "dashboard", stdin="not json at all")
        assert result.exception.code == "usage_error"
        assert "not JSON" in _refusal(result)

    def test_an_empty_payload_is_refused_with_the_reason(self) -> None:
        result = _invoke("ui", "dashboard", stdin="")
        assert result.exception.code == "usage_error"
        assert "nothing to render without one" in _refusal(result)

    def test_a_payload_missing_its_object_is_refused(self) -> None:
        result = _invoke("ui", "dashboard", stdin=json.dumps({}))
        assert result.exception.code == "usage_error"
        assert "ui.no_api_object" in _refusal(result)

    def test_a_file_payload_renders_the_same_as_stdin(self, tmp_path: Path) -> None:
        payload = tmp_path / "dashboard.json"
        payload.write_text(json.dumps(DASHBOARD_PAYLOAD), encoding="utf-8")
        from_file = _invoke("ui", "dashboard", "--payload", str(payload))
        from_stdin = _invoke("ui", "dashboard", stdin=json.dumps(DASHBOARD_PAYLOAD))
        assert from_file.exit_code == 0
        assert from_file.output == from_stdin.output

    def test_the_full_page_carries_its_api_path_and_its_caveats(self) -> None:
        result = _invoke(
            "ui",
            "dashboard",
            "--api-path",
            "/api/v1/dashboard",
            "--html",
            stdin=json.dumps(DASHBOARD_PAYLOAD),
        )
        assert result.exit_code == 0
        assert "/api/v1/dashboard" in result.output
        assert "what this page does not claim" in result.output

    def test_a_dashboard_number_with_no_evidence_is_refused(self) -> None:
        payload = json.loads(json.dumps(DASHBOARD_PAYLOAD))
        payload["numbers"][0]["evidence"] = []
        result = _invoke("ui", "dashboard", stdin=json.dumps(payload))
        assert result.exception.code == "usage_error"
        assert "ui.number_without_evidence" in _refusal(result)


def test_the_module_exports_the_group_under_one_name() -> None:
    """``mayhem.cli.api_cmd.api`` is the name a registrar will use."""
    assert api_cmd.__all__ == ["api", "openapi", "parameters", "render_ui", "routes", "ui"]
    assert api_cmd.api is api


@pytest.mark.parametrize("name", ["api", "routes", "openapi", "parameters", "render_ui", "ui"])
def test_every_exported_name_resolves(name: str) -> None:
    """Each name in ``__all__`` is something, so the export list cannot rot."""
    assert getattr(api_cmd, name) is not None
