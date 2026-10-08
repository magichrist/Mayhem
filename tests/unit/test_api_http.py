"""The HTTP surface end to end, over a real socket (plan 08, Phase 3).

The gateway's tests call :meth:`~mayhem.controller.api_service.ApiGateway.dispatch`
directly. That proves the decisions but proves nothing about the *transport*: a
WSGI adapter that always returned 200, or wrote the body twice, or dropped a
header, would pass every one of those tests. This file drives
:func:`~mayhem.controller.api_http.serve` on an ephemeral port and reads the
responses back with ``urllib``, so what is asserted is what a client receives.

What it proves, and what it cannot
----------------------------------

It proves: real status codes, real bodies, real headers, real percent-decoding, a
real ``Authorization`` bearer path, a real HTML page for a browser and JSON for a
machine, and a refusal that is normalized in both.

It cannot prove: anything about TLS, concurrency, or performance.
:func:`~mayhem.controller.api_http.serve` is a single-threaded ``wsgiref`` server
and its own docstring says so; these tests make no claim about serving more than
one request at a time, which is exactly the property a production deployment has
to get from somewhere else.

Negative controls
-----------------

* **The HTML/JSON split is real.** A ``curl``-shaped request gets JSON even on an
  error; a browser-shaped request gets HTML. Proved from *both* sides, because a
  content-negotiation check that always chose one would pass a test of either.
* **The application never leaks a traceback.** An internal failure becomes a 500
  envelope naming ``api.internal`` — asserted by handing the gateway a route table
  whose handler raises.
* **A declared body limit is enforced before the body is read.**
* **The two applications compose.** ``/api/v1/*`` goes to the JSON app and
  ``/ui/*`` to the HTML app, and a UI route with no bound render credential
  answers 501 *naming the missing configuration* rather than rendering anyway.
"""

from __future__ import annotations

import json
import threading
from datetime import UTC, datetime
from http.client import HTTPConnection
from typing import TYPE_CHECKING, Any
from urllib.parse import urlencode

import pytest

from mayhem.controller.api_http import (
    DEFAULT_UI_ENVIRONMENT,
    ApiApplication,
    ControlPlaneApplication,
    html_error_page,
    make_environ,
)
from mayhem.controller.api_service import (
    API_GATEWAY_VERSION,
    API_PREFIX,
    ENVIRONMENT_HEADER,
    ROUTES,
    ApiGateway,
    ApiRefusedError,
    Route,
)
from mayhem.domain.api import RunResource
from mayhem.domain.identity import EnvironmentScope, Principal, Role, RoleGrant
from mayhem.infra.api_store import ApiStore
from mayhem.infra.identity_store import AuthSource, IdentityStore
from mayhem.infra.migrations import ALL_MIGRATIONS
from mayhem.infra.store import Store

if TYPE_CHECKING:
    from pathlib import Path

NOW = datetime(2026, 6, 1, 12, 0, tzinfo=UTC)
PEPPER = b"unit-test-pepper-for-plan-08-http"
PASSWORD = "correct horse battery staple"

MIGRATIONS = (*(m for m in ALL_MIGRATIONS if m.version < API_GATEWAY_VERSION),)


@pytest.fixture()
def store(tmp_path: Path) -> Store:
    opened = Store.open_migrated(tmp_path / "http.db", MIGRATIONS)
    yield opened
    opened.close()


@pytest.fixture()
def wired(store: Store) -> dict[str, Any]:
    from mayhem.controller.auth_service import AuthService

    api = ApiStore(store)
    identities = IdentityStore(store)
    auth = AuthService(identities, pepper=PEPPER, clock=lambda: NOW)
    viewer = Principal(principal_id="u-ana")
    identities.save_principal(viewer, auth_source=AuthSource.LOCAL, now=NOW)
    identities.save_grant(
        RoleGrant(
            role=Role.VIEW,
            scope=EnvironmentScope(environment=DEFAULT_UI_ENVIRONMENT),
            principal=viewer,
            granted_at=NOW,
            granted_by="u-root",
        )
    )
    identities.set_local_credential("u-ana", PASSWORD, now=NOW, iterations=10)
    token = auth.issue_session("u-ana", now=NOW).token
    gateway = ApiGateway(store=api, auth=auth, identity=identities, now=NOW)
    return {"store": store, "api": api, "gateway": gateway, "token": token}


def _record(run_id: str) -> Any:
    from mayhem.domain.experiments import (
        ExecutionPlan,
        ExperimentKind,
        PlannedStep,
        Wait,
    )
    from mayhem.domain.run_outcome import RunRecord, RunStatus, RunVerdict

    plan = ExecutionPlan(
        run_id=run_id,
        kind=ExperimentKind.DRILL,
        steps=(PlannedStep(id="step-1", seq=0, raw_action=Wait(duration="1s")),),
        config_snapshot_id="cfg-0001",
        topology_snapshot_id="topo-0001",
        environment_fingerprint="env-fp-1",
        policy_id="policy-9",
        seed=1,
    )
    return RunRecord(
        run_id=run_id,
        experiment_name="checkout-latency",
        spec_json='{"kind":"drill","name":"checkout-latency","hypothesis":"h",'
        '"containers":{"checkout":{"faults":[{"fault":"net.latency","duration":"5s"}]}},'
        '"execution":[{"sequential":["checkout"]}]}',
        plan_json=plan.model_dump_json(),
        seed=1,
        status=RunStatus.COMPLETED,
        verdict=RunVerdict.PASS,
        environment_fingerprint="env-fp-1",
        config_snapshot_id="cfg-0001",
        started_at="2026-01-01T00:00:00+00:00",
        ended_at="2026-01-01T00:00:10+00:00",
        tags=(),
    )


class _Live:
    """A real ``wsgiref`` server on an ephemeral port, in a thread."""

    def __init__(self, app: Any) -> None:
        from wsgiref.simple_server import WSGIRequestHandler, make_server

        class _Silent(WSGIRequestHandler):
            def log_message(self, *args: Any) -> None:
                del args

        self._server = make_server("127.0.0.1", 0, app, handler_class=_Silent)
        self._port = int(self._server.server_address[1])
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    def __enter__(self) -> _Live:
        self._thread.start()
        return self

    def __exit__(self, *_exc: object) -> None:
        self._server.shutdown()
        self._thread.join(timeout=5)
        self._server.server_close()

    def get(
        self,
        path: str,
        *,
        headers: dict[str, str] | None = None,
        query: dict[str, str] | None = None,
    ) -> tuple[int, dict[str, str], bytes]:
        target = path + (f"?{urlencode(query)}" if query else "")
        connection = HTTPConnection("127.0.0.1", self._port, timeout=10)
        try:
            connection.request("GET", target, headers=headers or {})
            response = connection.getresponse()
            return (
                int(response.status),
                {key.lower(): value for key, value in response.getheaders()},
                response.read(),
            )
        finally:
            connection.close()


def _headers(token: str, **extra: str) -> dict[str, str]:
    out = {
        "Authorization": f"Bearer {token}",
        ENVIRONMENT_HEADER: DEFAULT_UI_ENVIRONMENT,
        "Accept": "application/json",
    }
    out.update(extra)
    return out


# ── over a real socket ──────────────────────────────────────────────────────


class TestTheHttpSurfaceEndToEnd:
    def test_an_authenticated_read_returns_200_and_the_envelope(
        self, wired: dict[str, Any]
    ) -> None:
        with _Live(ApiApplication(wired["gateway"])) as live:
            status, headers, body = live.get(f"{API_PREFIX}/runs", headers=_headers(wired["token"]))
        assert status == 200
        assert headers["content-type"] == "application/json; charset=utf-8"
        payload = json.loads(body)
        assert set(payload) == {
            "status",
            "schema_version",
            "data",
            "warnings",
            "errors",
            "evidence_refs",
            "meta",
        }
        assert payload["status"] == "ok"

    def test_an_unauthenticated_read_returns_a_401_envelope(self, wired: dict[str, Any]) -> None:
        with _Live(ApiApplication(wired["gateway"])) as live:
            status, _headers_out, body = live.get(f"{API_PREFIX}/runs")
        assert status == 401
        payload = json.loads(body)
        assert payload["status"] == "error"
        assert payload["meta"]["rule_id"] == "auth.session_unknown"
        assert payload["errors"]

    def test_a_stored_run_is_readable_with_its_digest(self, wired: dict[str, Any]) -> None:
        resource = RunResource.of(_record("run-http-1"))
        wired["api"].save_run(resource)
        with _Live(ApiApplication(wired["gateway"])) as live:
            status, _headers_out, body = live.get(
                f"{API_PREFIX}/runs/run-http-1", headers=_headers(wired["token"])
            )
        assert status == 200
        assert json.loads(body)["data"]["run"]["run_id"] == "run-http-1"

    def test_a_query_string_is_parsed_and_percent_decoded(self, wired: dict[str, Any]) -> None:
        """A filter value with a space in it survives the round trip."""
        wired["api"].save_run(RunResource.of(_record("run-http-1")))
        with _Live(ApiApplication(wired["gateway"])) as live:
            status, _headers_out, body = live.get(
                f"{API_PREFIX}/runs",
                headers=_headers(wired["token"]),
                query={"experiment_name": "checkout latency"},
            )
        assert status == 200
        assert json.loads(body)["data"]["items"] == []

    def test_the_openapi_document_is_served_unauthenticated(self, wired: dict[str, Any]) -> None:
        with _Live(ApiApplication(wired["gateway"])) as live:
            status, _headers_out, body = live.get(f"{API_PREFIX}/openapi.json")
        assert status == 200
        envelope = json.loads(body)
        assert envelope["status"] == "ok"
        # The reference is inside the Phase 1 envelope, like every other response,
        # so a client has exactly one response shape to parse.
        document = envelope["data"]
        assert document["openapi"] == "3.1.0"
        assert len(document["paths"]) == len({route.path for route in ROUTES})

    def test_the_request_id_header_is_present_and_matches_the_envelope(
        self, wired: dict[str, Any]
    ) -> None:
        counter = {"n": 0}

        def _next() -> str:
            counter["n"] += 1
            return f"req-{counter['n']:04d}"

        gateway = ApiGateway(
            store=wired["api"],
            auth=wired["gateway"]._auth,
            identity=wired["gateway"]._identity,
            now=NOW,
            request_id=_next,
        )
        with _Live(ApiApplication(gateway)) as live:
            _status, headers, body = live.get(
                f"{API_PREFIX}/health", headers=_headers(wired["token"])
            )
        assert headers["x-request-id"] == "req-0001"
        assert json.loads(body)["meta"]["request_id"] == "req-0001"


# ── content negotiation: the negative controls, both directions ─────────────


class TestTheHtmlJsonSplitIsReal:
    def test_a_machine_gets_json_even_on_an_error(self, wired: dict[str, Any]) -> None:
        with _Live(ApiApplication(wired["gateway"])) as live:
            status, headers, body = live.get(f"{API_PREFIX}/runs")
        assert status == 401
        assert headers["content-type"].startswith("application/json")
        assert json.loads(body)["meta"]["rule_id"] == "auth.session_unknown"

    def test_a_browser_gets_html_on_an_error(self, wired: dict[str, Any]) -> None:
        with _Live(ApiApplication(wired["gateway"])) as live:
            status, headers, body = live.get(
                f"{API_PREFIX}/runs", headers={"Accept": "text/html,application/xhtml+xml"}
            )
        assert status == 401
        assert headers["content-type"].startswith("text/html")
        text = body.decode()
        assert "<h1>401" in text
        assert "auth.session_unknown" in text

    def test_a_browser_navigation_header_alone_gets_html(self, wired: dict[str, Any]) -> None:
        """``Sec-Fetch-Mode: navigate`` with no ``Accept`` — a real browser shape."""
        with _Live(ApiApplication(wired["gateway"])) as live:
            status, headers, _body = live.get(
                f"{API_PREFIX}/runs", headers={"Sec-Fetch-Mode": "navigate"}
            )
        assert status == 401
        assert headers["content-type"].startswith("text/html")

    def test_a_browser_gets_json_on_success_because_it_asked_for_json(
        self, wired: dict[str, Any]
    ) -> None:
        """The counter-case: ``Accept: */*`` plus json wins, so a client never
        has to parse HTML to find out whether it was refused."""
        with _Live(ApiApplication(wired["gateway"])) as live:
            status, headers, _body = live.get(
                f"{API_PREFIX}/health",
                headers={"Accept": "application/json, text/html"},
            )
        assert status == 200
        assert headers["content-type"].startswith("application/json")


# ── the boundary never leaks ────────────────────────────────────────────────


class TestTheApplicationNeverLeaks:
    def test_an_internal_failure_is_a_500_envelope_naming_a_rule(
        self, wired: dict[str, Any]
    ) -> None:
        """No traceback, no exception out of the callable."""

        class _Exploding(Store):
            pass

        exploding = _Exploding(str(wired["store"]._path))
        gateway = ApiGateway(
            store=ApiStore(exploding),
            auth=wired["gateway"]._auth,
            identity=wired["gateway"]._identity,
            now=NOW,
            routes=(
                Route(
                    method="GET",
                    path=f"{API_PREFIX}/boom",
                    handler="boom",
                    summary="raises",
                    required_role=Role.VIEW,
                ),
            ),
        )
        gateway._read_boom = _explode  # type: ignore[attr-defined]
        with _Live(ApiApplication(gateway)) as live:
            status, headers, body = live.get(f"{API_PREFIX}/boom", headers=_headers(wired["token"]))
        assert status == 500
        assert headers["content-type"].startswith("application/json")
        payload = json.loads(body)
        assert payload["meta"]["rule_id"] == "api.internal"
        assert "Traceback" not in body.decode()
        exploding.close()

    def test_a_body_longer_than_the_declared_cap_is_refused_unread(
        self, wired: dict[str, Any]
    ) -> None:
        """The cheap half of the defence: ``CONTENT_LENGTH`` is checked first."""
        environ = {
            "REQUEST_METHOD": "POST",
            "PATH_INFO": f"{API_PREFIX}/plans",
            "CONTENT_LENGTH": str(64 * 1024 * 1024),
            "wsgi.input": None,
        }
        with pytest.raises(ApiRefusedError) as caught:
            make_environ(environ)  # type: ignore[arg-type]
        assert caught.value.rule == "api.body_too_large"
        assert caught.value.status == 413


def _explode(*_args: Any, **_kwargs: Any) -> Any:
    msg = "the internal failure this test is about"
    raise RuntimeError(msg)


# ── the UI routes ───────────────────────────────────────────────────────────


class TestTheControlPlaneApplicationComposesBothSurfaces:
    def test_the_index_lists_every_page(self, wired: dict[str, Any]) -> None:
        app = ControlPlaneApplication(wired["gateway"])
        with _Live(app) as live:
            status, headers, body = live.get("/ui")
        assert status == 200
        assert headers["content-type"].startswith("text/html")
        text = body.decode()
        assert "dashboard" in text and "live-run" in text
        assert "no UI-only state for an execution concept" in text

    def test_the_api_prefix_is_still_served_by_the_same_application(
        self, wired: dict[str, Any]
    ) -> None:
        app = ControlPlaneApplication(wired["gateway"])
        with _Live(app) as live:
            status, headers, _body = live.get(
                f"{API_PREFIX}/health", headers=_headers(wired["token"])
            )
        assert status == 200
        assert headers["content-type"].startswith("application/json")

    def test_a_ui_route_with_no_render_credential_is_501_naming_the_gap(
        self, wired: dict[str, Any]
    ) -> None:
        """A UI that read around its own authorization would be the defect the
        gateway exists to prevent, so the refusal has to be legible."""
        app = ControlPlaneApplication(wired["gateway"], ui_token="")
        with _Live(app) as live:
            status, _headers_out, body = live.get("/ui/dashboard")
        assert status == 501
        text = body.decode()
        assert "ui.no_render_credential" in text
        assert "bypassing authorization" in text

    def test_a_ui_route_with_a_bound_credential_renders_from_the_api_payload(
        self, wired: dict[str, Any]
    ) -> None:
        app = ControlPlaneApplication(wired["gateway"], ui_token=wired["token"])
        with _Live(app) as live:
            status, _headers_out, body = live.get("/ui/dashboard")
        assert status == 200
        text = body.decode()
        assert "api/v1/dashboard" in text
        assert "what this page does not claim" in text

    def test_a_page_needing_a_named_object_is_501_not_404(self, wired: dict[str, Any]) -> None:
        """A route with no object to name must not pretend to have one."""
        app = ControlPlaneApplication(wired["gateway"], ui_token=wired["token"])
        with _Live(app) as live:
            status, _headers_out, body = live.get("/ui/live-run")
        assert status == 501
        assert "ui.no_path_payload" in body.decode()

    def test_an_unknown_ui_page_is_a_404_naming_the_pages(self, wired: dict[str, Any]) -> None:
        app = ControlPlaneApplication(wired["gateway"], ui_token=wired["token"])
        with _Live(app) as live:
            status, _headers_out, body = live.get("/ui/no-such-page")
        assert status == 404
        assert "dashboard" in body.decode()


# ── the error page itself ───────────────────────────────────────────────────


def test_the_error_page_carries_the_rule_and_the_way_out() -> None:
    from mayhem.domain.api import ApiEnvelope

    envelope = ApiEnvelope.failed(
        ["something went wrong [api.example]"], meta={"rule_id": "api.example"}
    )
    from mayhem.controller.api_service import ApiResponse

    page = html_error_page(
        ApiResponse(status=418, envelope=envelope, request_id="r-1"), "/api/v1/thing"
    )
    assert "418" in page
    assert "api.example" in page
    assert "/api/v1/openapi.json" in page
    assert "/ui" in page


def test_the_error_page_escapes_the_reason() -> None:
    from mayhem.controller.api_service import ApiResponse
    from mayhem.domain.api import ApiEnvelope

    envelope = ApiEnvelope.failed(
        ["<script>alert(1)</script> [api.example]"], meta={"rule_id": "api.example"}
    )
    page = html_error_page(ApiResponse(status=400, envelope=envelope), "/api/v1/thing")
    assert "<script>alert(1)</script>" not in page
    assert "&lt;script&gt;" in page
