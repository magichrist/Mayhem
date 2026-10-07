"""Plan 06 Phase 3 — the ``mayhem cloud`` analysis surface, through the live tree.

Like plan 03's enrollment suite, this drives ``app`` — the registered tree, not
the group object — because a command nobody can reach would pass a group-level
test while being undispatchable.

The phase's acceptance is one refusal: an IAM-insufficient plan is refused with
the missing permission *named*. The tests below drive that refusal from both
sides — the default read-only role (missing ``target:mutate``) and a
partially-granted role (domain-satisfied but sandbox-refused on ``network``) —
and the positive side, where the two permission models agree and the answer is
``allowed``.

The honesty claims are asserted as output, not prose:

* every capability row reports ``mechanism_applied=false`` and the matrix says
  so in text mode — no transport ships, so nothing here has run against a
  provider;
* the cost estimate without a rate card is *refused*, printing the quantities
  to price and the word "unknown", never a zero that reads as "free";
* a declared ceiling the estimate cannot fit is refused before a mutation
  could ever read it;
* and the adapter is constructed over a stub transport that raises, so if an
  analysis path ever grew a provider call, the suite fails loudly here.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from click.testing import CliRunner

from mayhem.cli.app import app
from mayhem.cli.command_registry import COMMAND_HELP, COMMAND_SPECS
from mayhem.cli.exit_codes import ExitCode
from mayhem.domain.cloud import RULE_COST_CEILING_BELOW_HIGH
from mayhem.providers.cloud.port import CLOUD_COST_UNPRICED, CLOUD_DURATION_REQUIRED


def _run(*args: str) -> Any:
    result = CliRunner().invoke(app, list(args), catch_exceptions=False)
    assert isinstance(result.exit_code, int)
    return result


def _json(result: Any) -> dict[str, Any]:
    return json.loads(result.output)


# --- reachability -----------------------------------------------------------------


def test_cloud_group_is_registered_and_help_names_all_three_verbs() -> None:
    assert "cloud" in app.commands
    result = _run("cloud", "--help")
    assert result.exit_code == 0
    assert COMMAND_HELP["cloud"] in result.output
    for leaf in ("capabilities", "check-permission", "estimate-cost"):
        assert leaf in result.output


def test_registry_spec_declares_the_read_only_shape() -> None:
    spec = next(spec for spec in COMMAND_SPECS if spec.name == "cloud")
    assert spec.workflow == "inspect"
    assert spec.mutating is False


def test_every_leaf_parses_help() -> None:
    for leaf in ("capabilities", "check-permission", "estimate-cost"):
        result = _run("cloud", leaf, "--help")
        assert result.exit_code == 0


# --- capabilities -----------------------------------------------------------------


def test_capabilities_matrix_covers_all_three_providers_in_text() -> None:
    result = _run("cloud", "capabilities")
    assert result.exit_code == 0
    for provider in ("aws", "gcp", "azure"):
        assert f"{provider}:" in result.output
    # The honesty notice is part of the output, not a docstring.
    assert "applied=false" in result.output
    assert "the CloudTransport port has no implementation in this repository" in result.output


def test_capabilities_json_rows_are_honest() -> None:
    result = _run("cloud", "capabilities", "--json")
    assert result.exit_code == 0
    payload = _json(result)
    assert payload["mechanism_applied"] is False
    assert payload["count"] == len(payload["rows"])
    assert payload["count"] > 0
    providers = {row["provider"] for row in payload["rows"]}
    assert providers == {"aws", "gcp", "azure"}
    for row in payload["rows"]:
        assert row["mechanism_applied"] is False
        assert row["demonstrated_on_sandbox_account"] is False
        if row["reversible"]:
            assert row["compensate_operation"]
        else:
            assert row["compensate_operation"] is None
            assert row["irreversible_rationale"]
    # The irreversible set is derivable from the rows, so the two views agree.
    derived = {row["label"] for row in payload["rows"] if not row["reversible"]}
    assert set(payload["irreversible"]) == derived


def test_capabilities_single_provider_is_a_subset() -> None:
    everything = _json(_run("cloud", "capabilities", "--json"))
    aws_only = _json(_run("cloud", "capabilities", "--provider", "aws", "--json"))
    assert aws_only["providers"] == ["aws"]
    assert {row["label"] for row in aws_only["rows"]} <= {
        row["label"] for row in everything["rows"]
    }


# --- check-permission -------------------------------------------------------------


def _permission_args(**overrides: str) -> list[str]:
    args = [
        "cloud",
        "check-permission",
        "--provider",
        overrides.get("provider", "aws"),
        "--account",
        overrides.get("account", "acct-1"),
        "--region",
        overrides.get("region", "us-east-1"),
        "--resource-id",
        overrides.get("resource_id", "i-0abc123"),
        "--resource-class",
        overrides.get("resource_class", "vm"),
        "--kind",
        overrides.get("kind", "stop"),
        "--json",
    ]
    for grant in overrides.get("grants", "").split(","):
        if grant:
            args += ["--grant", grant]
    return args


def test_default_read_only_role_is_refused_naming_the_missing_permission() -> None:
    """The phase's acceptance, driven exactly as a default invocation reaches it."""
    result = _run(*_permission_args())
    assert result.exit_code == int(ExitCode.SAFETY_REFUSAL)
    payload = _json(result)
    assert payload["allowed"] is False
    assert "target:mutate" in payload["missing"]
    assert "target:mutate" in result.output


def test_refusal_names_sandbox_missing_adapter_permission() -> None:
    """The domain is satisfied, the sandbox is not, and the refusal says which."""
    result = _run(*_permission_args(grants="target:mutate"))
    assert result.exit_code == int(ExitCode.SAFETY_REFUSAL)
    payload = _json(result)
    assert payload["missing"] == []
    assert "network" in payload["adapter_missing"]
    assert "network" in result.output


def test_fully_granted_role_is_allowed() -> None:
    result = _run(*_permission_args(grants="target:mutate,network"))
    assert result.exit_code == int(ExitCode.SUCCESS)
    payload = _json(result)
    assert payload["allowed"] is True
    assert payload["missing"] == []
    assert payload["adapter_missing"] == []
    assert payload["action_id"] == "probe.aws.vm.stop"


def test_allowed_but_unsupported_action_still_says_so() -> None:
    """Grants answer the IAM question; they do not invent a capability row."""
    result = _run(*_permission_args(provider="aws", kind="reboot", grants="target:mutate,network"))
    assert result.exit_code == int(ExitCode.SUCCESS)
    payload = _json(result)
    assert payload["allowed"] is True
    assert payload["provider_supports_action"] is False


def test_default_role_is_refused_in_human_mode_with_the_permission_named() -> None:
    result = CliRunner().invoke(
        app,
        [
            "cloud",
            "check-permission",
            "--provider",
            "aws",
            "--account",
            "acct-1",
            "--region",
            "us-east-1",
            "--resource-id",
            "i-0abc123",
            "--resource-class",
            "vm",
            "--kind",
            "stop",
        ],
        catch_exceptions=False,
    )
    assert result.exit_code == int(ExitCode.SAFETY_REFUSAL)
    assert "refused" in result.output
    assert "target:mutate" in result.output


def test_wildcard_resource_id_is_a_validation_error_not_a_refusal() -> None:
    result = _run(*_permission_args(resource_id="*"))
    assert result.exit_code == int(ExitCode.VALIDATION_ERROR)


# --- estimate-cost ----------------------------------------------------------------


def _cost_args(**overrides: str) -> list[str]:
    args = [
        "cloud",
        "estimate-cost",
        "--provider",
        overrides.get("provider", "aws"),
        "--account",
        overrides.get("account", "acct-1"),
        "--region",
        overrides.get("region", "us-east-1"),
        "--resource-id",
        overrides.get("resource_id", "i-0abc123"),
        "--resource-class",
        overrides.get("resource_class", "vm"),
        "--kind",
        overrides.get("kind", "stop"),
        "--json",
    ]
    for key in (
        "duration_s",
        "rate_card_source",
        "micros_per_api_call",
        "micros_per_instance_hour",
        "micros_per_volume_operation",
        "high_factor",
        "ceiling",
    ):
        if key in overrides:
            args += [f"--{key.replace('_', '-')}", overrides[key]]
    return args


def test_unpriced_estimate_says_unknown_not_free() -> None:
    """No card, no ceiling: the zeros carry the domain's own honesty line."""
    result = _run(*_cost_args())
    assert result.exit_code == int(ExitCode.SUCCESS)
    payload = _json(result)
    assert payload["priced"] is False
    assert payload["expected_low"] == 0.0 and payload["expected_high"] == 0.0
    assert "no price is known" in payload["basis"]
    assert "not that the action is free" in payload["basis"]
    assert "api_calls=" in result.output


def test_unpriced_with_a_declared_ceiling_is_refused() -> None:
    """A declared limit cannot be honored by an estimate nobody can price."""
    result = _run(*_cost_args(ceiling="1000"))
    assert result.exit_code == int(ExitCode.SAFETY_REFUSAL)
    payload = _json(result)
    assert payload["priced"] is False
    assert payload["code"] == CLOUD_COST_UNPRICED
    assert "cannot certify an action it cannot price" in result.output
    human = CliRunner().invoke(
        app,
        [
            "cloud",
            "estimate-cost",
            "--provider",
            "aws",
            "--account",
            "acct-1",
            "--region",
            "us-east-1",
            "--resource-id",
            "i-0abc123",
            "--resource-class",
            "vm",
            "--kind",
            "stop",
            "--ceiling",
            "1000",
        ],
        catch_exceptions=False,
    )
    assert human.exit_code == int(ExitCode.SAFETY_REFUSAL)
    assert "unknown, not free" in human.output


def test_priced_estimate_from_operator_card_succeeds_under_a_ceiling() -> None:
    # stop/vm is reversible on aws: 2 mutate+verify calls plus 2 compensate+verify
    # = 4 api calls; 100 micros each prices the action at 400. The ceiling must
    # cover the high bound, because an estimate that cannot fit a declared limit
    # is refused by the domain at construction.
    result = _run(
        *_cost_args(
            rate_card_source="operator-portal-2026-10",
            micros_per_api_call="100",
            ceiling="1000",
        )
    )
    assert result.exit_code == int(ExitCode.SUCCESS)
    payload = _json(result)
    assert payload["priced"] is True
    assert payload["price_source"] == "operator-portal-2026-10"
    assert payload["counts"]["api_calls"] == 4
    assert "api_calls=4" in payload["counts_summary"]
    assert payload["expected_low"] == 400.0
    assert payload["expected_high"] == 400.0
    assert "operator-portal-2026-10" in result.output


def test_declared_ceiling_below_the_estimate_is_refused() -> None:
    result = _run(
        *_cost_args(
            rate_card_source="operator-portal-2026-10",
            micros_per_api_call="100",
            ceiling="100",
        )
    )
    assert result.exit_code == int(ExitCode.SAFETY_REFUSAL)
    payload = _json(result)
    assert payload["priced"] is True
    assert payload["code"] == RULE_COST_CEILING_BELOW_HIGH


def test_billable_capability_without_duration_is_refused() -> None:
    result = _run(
        *_cost_args(
            kind="impair",
            rate_card_source="operator-portal-2026-10",
            micros_per_api_call="100",
        )
    )
    assert result.exit_code == int(ExitCode.SAFETY_REFUSAL)
    payload = _json(result)
    assert payload["code"] == CLOUD_DURATION_REQUIRED


def test_unit_rates_without_a_named_source_are_a_validation_error() -> None:
    result = _run(*_cost_args(micros_per_api_call="100"))
    assert result.exit_code == int(ExitCode.VALIDATION_ERROR)


def test_priced_estimate_reports_the_denominator_in_human_mode() -> None:
    result = CliRunner().invoke(
        app,
        [
            "cloud",
            "estimate-cost",
            "--provider",
            "aws",
            "--account",
            "acct-1",
            "--region",
            "us-east-1",
            "--resource-id",
            "i-0abc123",
            "--resource-class",
            "vm",
            "--kind",
            "stop",
            "--rate-card-source",
            "operator-portal-2026-10",
            "--micros-per-api-call",
            "100",
            "--ceiling",
            "1000",
        ],
        catch_exceptions=False,
    )
    assert result.exit_code == int(ExitCode.SUCCESS)
    assert "api_calls=4" in result.output
    assert "operator-portal-2026-10" in result.output


# --- the stub transport ------------------------------------------------------------


def test_analysis_paths_never_reach_a_transport() -> None:
    """The stub is structural: a provider call on this surface fails loudly."""
    from mayhem.cli.cloud_cmd import _CALLS_REACH_NOTHING, _DeadTransport

    stub = _DeadTransport()
    with pytest.raises(RuntimeError, match=_CALLS_REACH_NOTHING[:40]):
        stub.list_resources(None)
    with pytest.raises(RuntimeError):
        stub.read_resource(None, "x")
    with pytest.raises(RuntimeError):
        stub.mutate(None)
