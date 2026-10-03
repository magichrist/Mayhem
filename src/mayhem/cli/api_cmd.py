"""``mayhem api`` — the operator surface for the ``/api/v1`` control plane and the
UI (plan 08, Phase 3).

Four subcommands, and each answers a question that has exactly one right answer
somewhere else in the repository:

* ``mayhem api routes`` — the route table, from
  :data:`mayhem.controller.api_service.ApiGateway.route_inventory`. It is *not* a
  hand-written list; a route added to the table appears here and a route removed
  from it disappears, so this command cannot document an endpoint that is not
  served.
* ``mayhem api openapi`` — the OpenAPI document,
  :func:`mayhem.controller.api_service.openapi_document`, generated from the same
  table. Phase 6's acceptance is "API reference generated from OpenAPI, never
  hand-maintained"; this command is where the reference comes from, and it
  ``--write``s a file so a repository can pin a copy without anyone editing it.
* ``mayhem api parameters`` — the parameter UX (gap 61) as the control table the
  UI renders, from
  :func:`mayhem.controller.api_service.parameter_controls`. ``--fault`` narrows it
  to one fault.
* ``mayhem api ui`` — render one UI page from a JSON payload on stdin or a file,
  through :func:`mayhem.controller.api_ui.render_page`. This is how the pages that
  need a *named* object (a run, a boundary report, a recommendation analysis) are
  rendered from the command line, and it is also how a reviewer looks at a page
  without standing up a server.

Not here
--------

``mayhem api serve`` is **not** in this module's command list, and that is
deliberate. :func:`mayhem.controller.api_http.serve` exists and works — the
end-to-end test drives a real socket through it — but binding a network listener
is a deployment action with a security surface (no TLS, no rate limit, no
threading, as that function's own docstring says), and putting it behind a
one-word CLI flag in the same command that prints a route table is how it gets
bound by accident. Wiring it up is the CLI inventory owner's change; the exact
call is one line and the function is public.

Nothing in this module mutates a control-plane record. Every subcommand is a read
or a renderer. ``serve`` is absent for the same reason the plan's rollout puts
mutations behind approval gates: a surface that only reads is a surface whose
worst mistake is a wrong sentence.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import click

from mayhem.cli import style
from mayhem.cli.errors import MayhemCliError

__all__ = [
    "api",
    "openapi",
    "parameters",
    "render_ui",
    "routes",
    "ui",
]


@click.group("api", invoke_without_command=False)
def api() -> None:
    """The control-plane API and UI: routes, reference, parameters, pages."""


@api.command("routes")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON.")
def routes(as_json: bool) -> None:
    """Every endpoint this build serves, with the role each one requires."""
    from mayhem.controller.api_service import ROUTES, UNIMPLEMENTED_API_SURFACES

    inventory = [
        {
            "method": route.method,
            "path": route.path,
            "summary": route.summary,
            "required_role": "" if route.required_role is None else route.required_role.value,
            "mutating": route.mutating,
            "command_path": route.command_path,
            "idempotent": route.idempotent,
        }
        for route in ROUTES
    ]
    if as_json:
        click.echo(
            json.dumps(
                {
                    "routes": inventory,
                    "count": len(inventory),
                    "unimplemented": list(UNIMPLEMENTED_API_SURFACES),
                },
                indent=2,
                sort_keys=True,
            )
        )
        return
    click.echo(f"{len(inventory)} endpoint(s) under /api/v1")
    for entry in inventory:
        role = entry["required_role"] or "none"
        command = f"  -> mayhem {entry['command_path']}" if entry["command_path"] else ""
        click.echo(f"  {entry['method']:<6} {entry['path']}")
        click.echo(f"         {entry['summary']}")
        click.echo(f"         role: {role}{command}")
    click.echo("")
    click.echo(style.warn("not served by this build:"))
    for surface in UNIMPLEMENTED_API_SURFACES:
        click.echo(f"  - {surface}")


@api.command("openapi")
@click.option(
    "--out",
    "out_path",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="Write the document to this file instead of stdout.",
)
def openapi(out_path: Path | None) -> None:
    """The API reference, generated from the route table."""
    from mayhem.controller.api_service import openapi_document

    document = json.dumps(openapi_document(), indent=2, sort_keys=True)
    if out_path is None:
        click.echo(document)
        return
    out_path.write_text(document + "\n", encoding="utf-8")
    click.echo(f"{style.ok('wrote')} {out_path}")


@api.command("parameters")
@click.option("--fault", "fault_id", default="", help="Only this fault's parameters.")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON.")
def parameters(fault_id: str, as_json: bool) -> None:
    """The parameter controls the UI renders, projected from the catalog schemas."""
    from mayhem.controller.api_service import parameter_controls

    controls = parameter_controls([fault_id] if fault_id else ())
    if as_json:
        click.echo(
            json.dumps(
                {"parameters": [row.to_payload() for row in controls], "count": len(controls)},
                indent=2,
                sort_keys=True,
            )
        )
        return
    if not controls:
        click.echo(style.warn(f"no catalog parameter is declared for {fault_id!r}"))
        return
    by_fault: dict[str, list[Any]] = {}
    for control in controls:
        by_fault.setdefault(control.fault_id, []).append(control)
    for name in sorted(by_fault):
        click.echo(style.cyan(name))
        for control in by_fault[name]:
            bounds = ""
            if control.minimum is not None or control.maximum is not None:
                bounds = f" [{control.minimum}..{control.maximum}] step={control.step}"
            caps = (
                f" needs {', '.join(control.required_capabilities)}"
                if control.required_capabilities
                else ""
            )
            click.echo(
                f"  {control.name:<24} {control.kind.value:<20} "
                f"risk={control.risk} default={control.default!r}{bounds}{caps}"
            )


def _pages() -> tuple[str, ...]:
    """The pages ``mayhem api ui`` will render.

    Read from the UI module's own :class:`~mayhem.controller.api_ui.PageId` so
    this list cannot advertise a page that has no renderer.
    """
    from mayhem.controller.api_ui import PageId

    return tuple(entry.value for entry in PageId)


@api.command("ui")
@click.argument("page", required=False, default="")
@click.option(
    "--payload",
    "payload_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help="Read the API payload from this file; omit to read stdin.",
)
@click.option("--api-path", default="", help="The API path this payload came from.")
@click.option("--html", "want_html", is_flag=True, help="Emit the full page, not the body.")
def render_ui(
    page: str, payload_path: Path | None, api_path: str, want_html: bool
) -> None:
    """Render one UI page from an API payload."""
    from mayhem.controller.api_ui import UiRenderRefusedError, render_page

    pages = _pages()
    if not page:
        click.echo(f"pages: {', '.join(pages)}")
        return
    if page not in pages:
        raise MayhemCliError(
            "usage_error",
            f"no UI page {page!r}; this build renders {', '.join(pages)}",
        )
    if payload_path is not None:
        raw = payload_path.read_text(encoding="utf-8")
    else:
        stream = sys.stdin
        raw = "" if stream is None else stream.read()
    if not raw.strip():
        raise MayhemCliError(
            "usage_error",
            "no payload was supplied; the page renders from an API payload, and there "
            "is nothing to render without one",
        )
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise MayhemCliError("usage_error", f"payload is not JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise MayhemCliError("usage_error", "payload must be a JSON object")
    try:
        rendered = render_page(page, payload, api_path=api_path or f"<{page} payload>")
    except UiRenderRefusedError as exc:
        raise MayhemCliError("usage_error", f"{exc.rule_id}: {exc.message}") from exc
    click.echo(rendered.to_html() if want_html else rendered.body_html)


@api.command("pages")
def ui() -> None:
    """Every UI page this build serves, and what each one is for."""
    from mayhem.controller.api_ui import ui_pages

    for entry in ui_pages():
        click.echo(f"  {entry['page']:<18} {entry['summary']}")
