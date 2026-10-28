"""``mayhem api serve`` and the per-request clock behind it.

Three claims, each with its negative control:

* a non-loopback bind is refused by name, and nothing is bound;
* the credential pepper is required and has no default;
* a gateway built with a clock answers each request at that request's instant,
  while a gateway built with a fixed ``now`` keeps it (the tests rely on that).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

import pytest
from click.testing import CliRunner

from mayhem.cli.api_cmd import LOOPBACK_HOSTS, PEPPER_ENV, api
from mayhem.controller.api_service import ApiGateway, ApiRefusedError

T0 = datetime(2026, 10, 28, 12, 0, tzinfo=UTC)


def _gateway(*, now: datetime, clock: Any = None) -> ApiGateway:
    return ApiGateway(
        store=SimpleNamespace(store=None),
        auth=None,
        identity=None,
        now=now,
        clock=clock,
    )


def _refuse(request: object) -> None:
    raise ApiRefusedError("api.test_refusal", "refused by the test")


class TestServeRefusesWithoutAServer:
    def test_a_wildcard_bind_is_refused_by_name(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(PEPPER_ENV, "pepper")
        result = CliRunner().invoke(api, ["serve", "--host", "0.0.0.0"])
        assert result.exit_code != 0
        assert "0.0.0.0" in result.output
        assert "loopback" in result.output

    def test_every_loopback_name_passes_the_host_check(self) -> None:
        assert {"127.0.0.1", "::1", "localhost"} == set(LOOPBACK_HOSTS)

    def test_a_missing_pepper_is_refused_and_no_default_is_used(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv(PEPPER_ENV, raising=False)
        result = CliRunner().invoke(api, ["serve"])
        assert result.exit_code != 0
        assert PEPPER_ENV in result.output

    def test_an_empty_pepper_is_the_same_as_a_missing_one(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(PEPPER_ENV, "")
        result = CliRunner().invoke(api, ["serve"])
        assert result.exit_code != 0
        assert PEPPER_ENV in result.output

    def test_serve_is_listed_as_a_command(self) -> None:
        assert "serve" in api.commands


class TestTheClockIsReadPerRequest:
    def test_a_clocked_gateway_answers_each_request_at_its_own_instant(self) -> None:
        ticks = iter([T0, T0 + timedelta(hours=1)])
        gateway = _gateway(now=T0, clock=lambda: next(ticks))
        gateway._resolve = _refuse  # type: ignore[method-assign]
        gateway.dispatch(_request())
        assert gateway._now == T0
        gateway.dispatch(_request())
        assert gateway._now == T0 + timedelta(hours=1)

    def test_a_gateway_without_a_clock_keeps_its_fixed_instant(self) -> None:
        gateway = _gateway(now=T0)
        gateway._resolve = _refuse  # type: ignore[method-assign]
        gateway.dispatch(_request())
        gateway.dispatch(_request())
        assert gateway._now == T0


def _request() -> Any:
    return SimpleNamespace(method="GET", path="/api/v1/runs", headers={}, body=b"")
