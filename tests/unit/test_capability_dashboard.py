"""v0.9.0 expansion task 11: capability truth dashboard."""

from __future__ import annotations

import json

import pytest
from click.testing import CliRunner

from mayhem.infra.catalog_report import build_capability_dashboard, build_capability_statuses


def _rows(engine: str | None = None):
    return build_capability_statuses(engine=engine)


def test_dashboard_covers_every_engine_and_fault() -> None:
    dashboard = build_capability_dashboard()
    assert dashboard.rows
    assert {row.engine for row in dashboard.rows} == {"docker", "podman", "kubernetes"}
    assert dashboard.schema_version == "1.0"
    assert dashboard.generated_at


def test_dashboard_rows_carry_family_maturity_source_and_remediation() -> None:
    dashboard = build_capability_dashboard(engine="docker")
    for row in dashboard.rows:
        assert row.fault_id.split(".", 1)[0] == row.family
        assert row.maturity
        assert row.source_of_truth
        if row.blocked_reason:
            assert row.remediation, f"{row.fault_id} is blocked with no remediation"
        else:
            assert row.remediation == ""


def test_blocked_rows_name_a_source_of_truth_and_next_step() -> None:
    blocked = [row for row in build_capability_dashboard().rows if row.blocked_reason]
    assert blocked
    for row in blocked:
        assert row.source_of_truth
        assert row.remediation


def test_catalog_only_rows_are_visible_and_not_supported() -> None:
    rows = [
        row
        for row in build_capability_dashboard(engine="docker").rows
        if "catalog" in row.remediation
    ]
    assert rows
    for row in rows:
        assert row.supported is False
        assert "catalog-only" in row.remediation


def test_unit_verified_rows_are_flagged_and_live_is_never_claimed() -> None:
    rows = build_capability_dashboard().rows
    assert any(row.unit_verified for row in rows)
    assert all(row.live_verified is False for row in rows)


def test_filters_by_engine_family_maturity_and_blocked() -> None:
    everything = build_capability_dashboard()
    only_k8s = everything.filtered(engine="kubernetes")
    assert {row.engine for row in only_k8s.rows} == {"kubernetes"}
    assert "engine" in only_k8s.filters

    first_family = everything.rows[0].family
    by_family = everything.filtered(family=first_family)
    assert by_family.rows
    assert {row.family for row in by_family.rows} == {first_family}

    band = everything.rows[0].maturity_band
    by_maturity = everything.filtered(maturity=band)
    assert {row.maturity_band for row in by_maturity.rows} == {band}

    blocked = everything.filtered(blocked=True)
    assert blocked.rows
    assert all(row.blocked_reason for row in blocked.rows)
    supported = everything.filtered(blocked=False)
    assert all(not row.blocked_reason for row in supported.rows)


def test_filters_compose_and_are_reported() -> None:
    dashboard = build_capability_dashboard().filtered(engine="kubernetes", blocked=True)
    assert set(dashboard.filters) == {"engine", "blocked"}
    assert {row.engine for row in dashboard.rows} == {"kubernetes"}


def test_summary_counts_match_rows() -> None:
    dashboard = build_capability_dashboard()
    summary = dashboard.summary()
    assert summary["total"] == len(dashboard.rows)
    assert summary["supported"] == sum(1 for row in dashboard.rows if row.supported)
    assert summary["blocked"] == sum(1 for row in dashboard.rows if row.blocked_reason)


def test_find_returns_every_engine_for_one_fault() -> None:
    dashboard = build_capability_dashboard()
    fault_id = dashboard.rows[0].fault_id
    found = dashboard.find(fault_id)
    assert found
    assert {row.fault_id for row in found} == {fault_id}


def test_to_dict_is_json_serializable_and_versioned() -> None:
    payload = build_capability_dashboard(engine="docker").to_dict()
    assert json.loads(json.dumps(payload))["schema_version"] == "1.0"
    assert payload["summary"]["total"] == len(payload["capabilities"])


@pytest.mark.parametrize("fmt", ["json", "yaml"])
def test_cli_emits_machine_formats(fmt: str) -> None:
    from mayhem.cli.toolkit import capabilities

    result = CliRunner().invoke(capabilities, ["--engine", "docker", "--format", fmt])
    assert result.exit_code == 0, result.output
    if fmt == "json":
        payload = json.loads(result.output)
        assert payload["capabilities"]
    else:
        assert "capabilities:" in result.output


def test_cli_text_output_shows_remediation_for_blocked_rows() -> None:
    from mayhem.cli.toolkit import capabilities

    result = CliRunner().invoke(capabilities, ["--engine", "docker", "--blocked"])
    assert result.exit_code == 0, result.output
    assert "source:" in result.output
    assert "maturity=" in result.output


def test_cli_explain_filters_to_one_fault() -> None:
    from mayhem.cli.toolkit import capabilities

    result = CliRunner().invoke(capabilities, ["--explain", "k8s.pod_kill", "--json"])
    assert result.exit_code == 0, result.output
    rows = json.loads(result.output)["capabilities"]
    assert rows
    assert {row["fault_id"] for row in rows} == {"k8s.pod_kill"}


def test_cli_explain_rejects_unknown_fault() -> None:
    from mayhem.cli.toolkit import capabilities

    result = CliRunner().invoke(capabilities, ["--explain", "nope.nope", "--json"])
    assert result.exit_code != 0
