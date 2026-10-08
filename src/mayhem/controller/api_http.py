"""The WSGI adapter: ``environ`` in, :class:`~mayhem.controller.api_service.ApiResponse`
out. Nothing else (plan 08, Phase 3).

This module is the whole of plan 08's HTTP surface: one page of translation.
Every decision — routing, authorisation, pagination, idempotency,
envelope shape — belongs to :mod:`mayhem.controller.api_service`; what is here is
the mapping from PEP 3333's ``environ`` to an
:class:`~mayhem.controller.api_service.ApiRequest` and back, plus the HTML error
page for a browser.

Why WSGI, and why this
----------------------

**There is no web framework in this project.** The declared dependencies are
pydantic, typer, click, pyyaml, structlog, and kubernetes; ``wsgiref`` is in the
standard library. Choosing WSGI means the control plane adds **no dependency**,
runs on the interpreter mayhem already ships, and can be exercised by calling the
callable directly — which is what makes the end-to-end tests about status codes
and bodies rather than about a client library's opinion of a status code.

It also means what it means and nothing more. Concretely, and stated here because
a reader will assume otherwise:

* **No HTTPS, no TLS termination, no HSTS, no CORS.** A WSGI callable is an
  application protocol, not a security control. A deployment terminates TLS in
  front of it. There is no ``Access-Control-Allow-Origin`` header emitted, so a
  browser on another origin cannot read a response — the default-deny that costs
  nothing and is correct until somebody asks for cross-origin deliberately.
* **No request-size limit at the socket.**
  :meth:`mayhem.controller.api_service.ApiRequest.json_body` refuses a body above
  :data:`~mayhem.controller.api_service.MAX_BODY_BYTES`, and
  :func:`make_environ` refuses a ``CONTENT_LENGTH`` above it *without reading the
  body at all* — but a request that declares no length is still bounded by
  whatever the reverse proxy allows. Set ``client_max_body_size`` there; this
  process does not enforce it.
* **No compression, no keep-alive tuning, no range requests.** Not asked for and
  not needed by a control plane whose payloads are small and read by machines
  more often than by browsers.

The server
----------

:func:`serve` uses :class:`wsgiref.simple_server.make_server` and nothing else.
That server is **single-threaded and unsuitable for production**; it is here so
that ``mayhem api serve`` works on a laptop and so the end-to-end test can drive
a real socket. :func:`serve` says so in its own docstring and in what it prints.
Threading it is a deployment decision, not a hidden default.
"""

from __future__ import annotations

import html
import json
from typing import TYPE_CHECKING, Any, Final
from urllib.parse import unquote_plus
from wsgiref.simple_server import WSGIRequestHandler, make_server

from mayhem.controller.api_service import (
    ENVIRONMENT_HEADER,
    MAX_BODY_BYTES,
    ApiGateway,
    ApiRefusedError,
    ApiRequest,
    ApiResponse,
)
from mayhem.controller.api_ui import (
    PageId,
    UiRenderRefusedError,
    render_page,
    ui_pages,
)
from mayhem.domain.api import ApiEnvelope

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable, Mapping, Sequence

__all__ = [
    "DEFAULT_UI_ENVIRONMENT",
    "HTML_CONTENT_TYPE",
    "JSON_CONTENT_TYPE",
    "ApiApplication",
    "ControlPlaneApplication",
    "html_error_page",
    "make_environ",
    "serve",
]

JSON_CONTENT_TYPE: Final[str] = "application/json; charset=utf-8"
HTML_CONTENT_TYPE: Final[str] = "text/html; charset=utf-8"

#: The environment an internal UI render resolves roles in. Spelled as a constant
#: so it is a value somebody changes deliberately rather than a string written in
#: two places; it is ``staging`` because that is the scope a control-plane viewer
#: is granted in the smallest useful deployment, and a deployment that wants a
#: different one changes this and its grants together.
DEFAULT_UI_ENVIRONMENT: Final[str] = "staging"

#: Where a browser may go next after a refusal. Only the API root and the UI
#: root, because those are the two things this build actually serves.
_SITE_LINKS: Final[tuple[tuple[str, str], ...]] = (
    ("/ui", "control plane UI"),
    ("/api/v1/openapi.json", "API reference"),
)


class ApiApplication:
    """A WSGI application over one :class:`ApiGateway`.

    ``now`` is not read here: the gateway owns the clock and every handler takes
    its instant from it, so this callable has no way to produce a
    time-dependent answer of its own.
    """

    def __init__(self, gateway: ApiGateway, *, request_id: Callable[[], str] | None = None) -> None:
        self._gateway = gateway
        self._request_id = request_id

    @property
    def gateway(self) -> ApiGateway:
        return self._gateway

    def __call__(
        self,
        environ: Mapping[str, Any],
        start_response: Callable[[str, list[tuple[str, str]]], Any],
    ) -> Iterable[bytes]:
        """Answer one request. Never raises: every failure is a response."""
        request = make_environ(environ, request_id=self._request_id)
        try:
            response = self._gateway.dispatch(request)
        except ApiRefusedError as exc:
            # A refusal raised *outside* ``dispatch`` — by ``make_environ``'s
            # size check, or by a handler the gateway routed to but could not
            # build. Still a response, because a control plane that 500s with a
            # traceback has told an operator nothing.
            response = ApiResponse(
                status=exc.status,
                envelope=_failed(str(exc), exc.rule),
                request_id="",
            )
        except Exception as exc:  # the boundary must never leak a traceback
            response = ApiResponse(
                status=500,
                envelope=_failed(
                    f"the control plane failed to answer this request: {exc} [api.internal]",
                    "api.internal",
                ),
                request_id="",
            )
        wants_html = _wants_html(request)
        body = (
            html_error_page(response, request.path).encode("utf-8")
            if wants_html and not response.ok
            else response.body_json().encode("utf-8")
        )
        content_type = HTML_CONTENT_TYPE if wants_html else JSON_CONTENT_TYPE
        headers = [
            ("Content-Type", content_type),
            ("Content-Length", str(len(body))),
            ("X-Request-Id", response.request_id),
            # Default-deny CORS. A browser on another origin cannot read a
            # response, and a deployment that needs cross-origin says so
            # explicitly rather than inheriting a permissive default.
            ("Vary", "Authorization, X-Mayhem-Environment, Idempotency-Key"),
        ]
        headers.extend((key, value) for key, value in response.headers.items())
        start_response(f"{response.status} {_reason(response.status)}", headers)
        return [body]


def make_environ(
    environ: Mapping[str, Any], *, request_id: Callable[[], str] | None = None
) -> ApiRequest:
    """``environ`` to :class:`ApiRequest`.

    Query parameters are parsed into a plain ``dict[str, str]``: a repeated key
    keeps its **first** value rather than becoming a list, because every filter
    this gateway accepts is a scalar and a list would have to be rejected
    somewhere downstream. Rejecting it here instead would be better; it is
    recorded as a known limitation rather than half-fixed.

    A body is read only up to :data:`MAX_BODY_BYTES`, and a ``CONTENT_LENGTH``
    above that is refused without the body entering memory at all.
    """
    raw_query = str(environ.get("QUERY_STRING", ""))
    query: dict[str, str] = {}
    if raw_query:
        for chunk in raw_query.split("&"):
            key, _, value = chunk.partition("=")
            query.setdefault(_unquote(key), _unquote(value))
    headers = {
        key[5:].replace("_", "-").lower(): str(value)
        for key, value in environ.items()
        if key.startswith("HTTP_")
    }
    if environ.get("CONTENT_TYPE"):
        headers["content-type"] = str(environ["CONTENT_TYPE"])
    declared = int(environ.get("CONTENT_LENGTH") or 0)
    if declared > MAX_BODY_BYTES:
        raise ApiRefusedError(
            "api.body_too_large",
            f"the request declares a {declared}-byte body, above the "
            f"{MAX_BODY_BYTES}-byte maximum this gateway reads",
            status=413,
            remediation="send the resource, not a dump of the table",
        )
    stream = environ.get("wsgi.input")
    body = stream.read(MAX_BODY_BYTES) if declared and stream is not None else b""
    path = str(environ.get("PATH_INFO", "")) or "/"
    request = ApiRequest(
        method=str(environ.get("REQUEST_METHOD", "GET")).upper(),
        path=path,
        query=query,
        headers=headers,
        body=body,
    )
    del request_id  # the gateway mints ids; the adapter never invents one
    return request


class ControlPlaneApplication:
    """The whole control plane over one socket: ``/ui/*`` and ``/api/v1/*``.

    Two applications, one callable. The split is the UI principle made structural:
    a page is rendered **from the payload the API returned for the same object**,
    obtained by calling :meth:`ApiGateway.dispatch` internally. There is no second
    read path, so there is no second answer, and the UI cannot render a run the
    API would refuse to show.

    ``ui_token`` and ``ui_environment`` are the *internal render credential*:
    rendering the dashboard requires reading ``GET /api/v1/dashboard``, and that
    read is authorized exactly like any other — there is no privileged internal
    path that skips the gateway. With no ``ui_token`` configured those two routes
    answer ``501`` naming the missing configuration, because a UI that quietly
    read around its own authorization would be the exact defect the gateway
    exists to prevent.

    Only the two pages whose payload is a whole-collection read are routable
    here: the dashboard, and the builder's parameter-control table. A page that
    needs a *particular* run, experiment, boundary report, or recommendation
    analysis is rendered by a caller through
    :func:`mayhem.controller.api_ui.render_page` with the payload the caller
    already holds — a path with no run id is not a page, and guessing one is how a
    UI starts showing somebody else's run.
    """

    def __init__(
        self,
        gateway: ApiGateway,
        *,
        request_id: Callable[[], str] | None = None,
        ui_token: str = "",
        ui_environment: str = DEFAULT_UI_ENVIRONMENT,
    ) -> None:
        self._gateway = gateway
        self._api = ApiApplication(gateway, request_id=request_id)
        self._ui_token = ui_token
        self._ui_environment = ui_environment

    @property
    def gateway(self) -> ApiGateway:
        return self._gateway

    def __call__(
        self,
        environ: Mapping[str, Any],
        start_response: Callable[[str, list[tuple[str, str]]], Any],
    ) -> Iterable[bytes]:
        path = str(environ.get("PATH_INFO", "")) or "/"
        if not path.startswith("/ui"):
            return self._api(environ, start_response)
        return self._ui(path, start_response)

    def _ui(
        self,
        path: str,
        start_response: Callable[[str, list[tuple[str, str]]], Any],
    ) -> Iterable[bytes]:
        tail = path[len("/ui") :].strip("/")
        if not tail:
            status, code, body = 200, "OK", _ui_index(ui_pages())
        elif tail in {entry.value for entry in PageId}:
            status, code, body = self._routed_page(PageId(tail), path)
        else:
            status, code = 404, "Not Found"
            body = (
                "<!doctype html><html><body><h1>404</h1><p>"
                f"no UI page at {html.escape(path)}</p><p>pages: "
                + html.escape(", ".join(entry["page"] for entry in ui_pages()))
                + "</p></body></html>"
            ).encode()
        start_response(
            f"{status} {code}",
            [
                ("Content-Type", HTML_CONTENT_TYPE),
                ("Content-Length", str(len(body))),
                ("X-Request-Id", ""),
            ],
        )
        return [body]

    def _routed_page(self, page_id: PageId, path: str) -> tuple[int, str, bytes]:
        """Render one routable page, or refuse with the reason it cannot be."""
        api_path = _UI_API_PATHS.get(page_id, "")
        if not api_path:
            return (
                501,
                "Not Implemented",
                _ui_refusal(
                    f"this page is rendered by a caller that already holds its payload "
                    f"({page_id.value}); there is no path that names the object for it. "
                    "Call mayhem.controller.api_ui.render_page instead.",
                    "ui.no_path_payload",
                ),
            )
        if not self._ui_token:
            return (
                501,
                "Not Implemented",
                _ui_refusal(
                    "no internal render credential is configured for the UI routes, so "
                    "this page cannot read its payload through the gateway without "
                    "bypassing authorization. Bind one when constructing "
                    "ControlPlaneApplication(ui_token=...).",
                    "ui.no_render_credential",
                ),
            )
        request = _internal_request(api_path, self._ui_token, self._ui_environment)
        response = self._gateway.dispatch(request)
        if not response.ok:
            return (
                502,
                "Bad Gateway",
                _ui_refusal(
                    "the API refused this page's own read, so it is not rendered: "
                    + "; ".join(response.envelope.errors),
                    str(response.envelope.meta.get("rule_id", "api.read_refused")),
                ),
            )
        try:
            page = render_page(page_id, response.envelope.data, api_path=api_path)
        except UiRenderRefusedError as exc:
            return (
                502,
                "Bad Gateway",
                _ui_refusal(exc.message, exc.rule_id),
            )
        return (200, "OK", page.to_html().encode("utf-8"))


#: Which pages are routable without a named object, and which API read each one
#: renders from. Two entries, both whole-collection reads. A page absent from this
#: table is a caller-rendered page, and the route says so rather than 404ing a
#: link the index advertises.
_UI_API_PATHS: Final[dict[PageId, str]] = {
    PageId.DASHBOARD: "/api/v1/dashboard",
    PageId.BUILDER: "/api/v1/parameters",
}


def _internal_request(api_path: str, token: str, environment: str) -> ApiRequest:
    """The internal render's request, carrying the configured credential.

    An ordinary :class:`~mayhem.controller.api_service.ApiRequest` with the real
    credential — not a privileged flag, not a bypass header. If the token is
    expired, revoked, or lacks ``VIEW`` in ``environment``, the gateway refuses
    and the page does not render, which is the behaviour an operator would want.
    """
    return ApiRequest(
        method="GET",
        path=api_path,
        headers={
            "authorization": f"Bearer {token}",
            ENVIRONMENT_HEADER: environment,
            "accept": "application/json",
        },
    )


def _ui_refusal(reason: str, rule: str) -> bytes:
    return (
        '<!doctype html><html lang="en"><body>'
        "<h1>this page is not rendered</h1>"
        f"<p>{html.escape(reason)}</p>"
        f"<p>rule: <code>{html.escape(rule)}</code></p>"
        "</body></html>"
    ).encode()


def serve(
    gateway: ApiGateway,
    *,
    host: str = "127.0.0.1",
    port: int = 8787,
    request_id: Callable[[], str] | None = None,
) -> Any:
    """Serve *gateway* over ``wsgiref`` until interrupted.

    .. warning::

       **This is a development server.** :class:`wsgiref.simple_server.WSGIServer`
       is single-threaded, speaks HTTP/1.0, and has no timeout, no TLS, and no
       access log beyond what ``wsgiref`` prints. It is here so ``mayhem api
       serve`` runs with no dependency and so the end-to-end test can drive a
       real socket; putting it on a network interface that is not loopback is the
       operator's mistake and the banner it prints says so.
    """
    app = ApiApplication(gateway, request_id=request_id)
    return make_server(host, port, app, handler_class=_QuietHandler)


class _QuietHandler(WSGIRequestHandler):
    """A request handler that does not write a line per request to stderr.

    Mayhem's own logging is structured (:mod:`mayhem.observability`); a default
    ``wsgiref`` access log interleaved with it is noise, and the request id in
    every response header is the traceable one.
    """

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 - stdlib signature
        del format, args


def html_error_page(response: ApiResponse, path: str) -> str:
    """A refusal, rendered for a human with a browser.

    Deliberately plain: no CSS framework, no bundler, no JavaScript. The page
    carries the rule id, the reason, and where to go next — the three things an
    operator needs — and nothing else. A styled error page would be a design
    system this build does not have, and pretending otherwise is the overclaim
    Phase 6 exists to prevent.
    """
    errors = response.envelope.errors or ("no reason was recorded",)
    rule = str(response.envelope.meta.get("rule_id", ""))
    rows = "".join(f"<li>{html.escape(str(error))}</li>" for error in errors)
    links = "".join(
        f'<li><a href="{html.escape(target)}">{html.escape(label)}</a></li>'
        for target, label in _SITE_LINKS
    )
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        f"<title>mayhem: {response.status}</title></head><body>"
        f"<h1>{response.status} — mayhem refused this request</h1>"
        f"<p>path: <code>{html.escape(path)}</code></p>"
        f"<p>rule: <code>{html.escape(rule)}</code></p>"
        f"<ul>{rows}</ul>"
        f"<h2>where to go next</h2><ul>{links}</ul>"
        "</body></html>"
    )


def _failed(reason: str, rule: str) -> ApiEnvelope:
    return ApiEnvelope.failed([f"{reason} [{rule}]"], meta={"rule_id": rule})


def _wants_html(request: ApiRequest) -> bool:
    """Whether this request came from a browser rather than a machine.

    Two signals, both standard: an ``Accept`` header that names ``text/html``, and
    a browser's ``Sec-Fetch-Mode: navigate``. An API client that sets neither gets
    JSON regardless, so a curl pipeline never has to parse HTML to find out it
    was refused.
    """
    accept = request.header("accept").lower()
    if "application/json" in accept:
        return False
    return "text/html" in accept or request.header("sec-fetch-mode") == "navigate"


def _ui_index(pages: Sequence[Mapping[str, str]]) -> bytes:
    """The ``/ui`` index: every page this build serves, and the UI principle.

    It says out loud that every page is rendered from an API payload, because a
    control plane whose index implies a UI-only state model is exactly the drift
    this module was written to prevent.
    """
    rows = "".join(
        f'<li><a href="/ui/{html.escape(str(entry["page"]))}">'
        f"{html.escape(str(entry['page']))}</a> — {html.escape(str(entry['summary']))}</li>"
        for entry in pages
    )
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        "<title>mayhem — control plane</title></head><body>"
        "<h1>mayhem control plane</h1>"
        f"<ul>{rows}</ul>"
        '<p><a href="/api/v1/openapi.json">API reference</a></p>'
        "<p>every page here is rendered from the payload the API returned for the same "
        "object; there is no UI-only state for an execution concept.</p>"
        "</body></html>"
    ).encode()


def _reason(status: int) -> str:
    return {
        200: "OK",
        400: "Bad Request",
        401: "Unauthorized",
        403: "Forbidden",
        404: "Not Found",
        405: "Method Not Allowed",
        409: "Conflict",
        413: "Content Too Large",
        500: "Internal Server Error",
        501: "Not Implemented",
    }.get(status, "Unknown")


def _unquote(value: str) -> str:
    return unquote_plus(value)


def render_json(envelope: ApiEnvelope) -> str:
    """The body bytes for *envelope*, sorted keys, no whitespace.

    Sorted keys are what make :class:`ApiResponse.body_json` reproducible, and
    reproducibility is what makes an idempotency replay byte-identical rather than
    merely equivalent.
    """
    return json.dumps(envelope.to_dict(), sort_keys=True, separators=(",", ":"))
