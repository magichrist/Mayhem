from __future__ import annotations

from mayhem.domain.redaction import redact, redact_text


def test_redacts_nested_secret_keys() -> None:
    result = redact(
        {
            "password": "hunter2",
            "nested": {"registry_token": "abc", "safe": "visible"},
            "items": [{"secret_value": "no"}],
        }
    )
    assert result.value["password"] == "***REDACTED***"
    assert result.value["nested"]["registry_token"] == "***REDACTED***"
    assert result.value["nested"]["safe"] == "visible"
    assert result.value["items"][0]["secret_value"] == "***REDACTED***"
    assert result.removed_paths


def test_redacts_url_credentials_and_assignments() -> None:
    value, changed = redact_text("registry=ghcr.io user=alice password=hunter2")
    assert changed is True
    assert "hunter2" not in value
    url, url_changed = redact_text("https://alice:hunter2@example.test/path")
    assert url_changed is True
    assert "hunter2" not in url
    assert "***:***" in url


def test_redacts_argv_and_preserves_shape() -> None:
    result = redact(["tool", "--token=abc", "target"])
    assert result.value == ["tool", "--token=***REDACTED***", "target"]


def test_redaction_is_recursive_for_lists_and_tuples() -> None:
    result = redact({"values": ("token=abc", "safe")})
    assert result.value["values"][0] == "token=***REDACTED***"
    assert result.value["values"][1] == "safe"


def test_evidence_records_redaction_metrics_without_secret_values() -> None:
    from mayhem.infra.evidence import build_evidence

    envelope = build_evidence(
        run_id="r1",
        plan=None,
        target_profile=None,
        engine="kubernetes",
        safety_decisions=(),
        step_reports=({"detail": "ok", "password": "hunter2"},),
        lease_timeline=(),
        observations=(),
        verdict="pass",
        recovery_state="none",
        remediation=(),
    )
    metrics = envelope.redaction_metrics
    assert metrics["redacted_path_count"] >= 1
    assert metrics["policy_version"]
    assert "hunter2" not in str(envelope.model_dump(mode="json"))


def test_redacts_bearer_and_authorization_credentials() -> None:
    value, changed = redact_text("Authorization: Bearer prom-secret-token-value")
    assert changed is True
    assert "prom-secret-token-value" not in value
    assert "Bearer ***REDACTED***" in value
    bare, bare_changed = redact_text("sent bearer ghp_abcdefgh12345 upstream")
    assert bare_changed is True
    assert "ghp_abcdefgh12345" not in bare


def test_redaction_keeps_non_credential_text_intact() -> None:
    value, changed = redact_text("bearer of the bad news")
    assert changed is False
    assert value == "bearer of the bad news"
