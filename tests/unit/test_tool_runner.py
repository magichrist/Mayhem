"""tool_runner + hashing: evidence capture and deterministic digests."""

import sys

import pytest

from tgondi.toolkit.hashing import canonical_json, digest, digest_mapping
from tgondi.toolkit.tool_runner import ToolError, ToolTimeoutError, run_tool


class TestHashing:
    def test_canonical_json_is_key_order_insensitive(self) -> None:
        assert canonical_json({"b": 1, "a": 2}) == canonical_json({"a": 2, "b": 1})

    def test_digest_stability(self) -> None:
        assert digest({"x": [1, 2, {"y": "z"}]}) == digest({"x": [1, 2, {"y": "z"}]})

    def test_digest_discriminates(self) -> None:
        assert digest("a") != digest(["a"])

    def test_digest_mapping_matches_digest_of_dict(self) -> None:
        assert digest_mapping({"k": "v"}) == digest({"k": "v"})


class TestRunTool:
    def test_echo_success(self) -> None:
        result = run_tool([sys.executable, "-c", "print('hello')"])
        assert result.succeeded
        assert result.exit_code == 0
        assert "hello" in result.stdout
        assert result.duration_ms >= 0
        assert not result.truncated

    def test_nonzero_exit_is_not_an_exception(self) -> None:
        result = run_tool([sys.executable, "-c", "import sys; sys.exit(3)"])
        assert result.exit_code == 3
        assert not result.succeeded

    def test_stderr_captured(self) -> None:
        result = run_tool([sys.executable, "-c", "import sys; sys.stderr.write('boom')"])
        assert "boom" in result.stderr

    def test_argv_digest_deterministic_and_order_sensitive(self) -> None:
        a = run_tool([sys.executable, "-c", "pass"])
        b = run_tool([sys.executable, "-c", "pass"])
        c = run_tool([sys.executable, "-c", "'pass'"])
        assert a.argv_digest == b.argv_digest
        assert a.argv_digest != c.argv_digest
        assert a.env_digest == b.env_digest

    def test_explicit_env_changes_env_digest(self) -> None:
        base = run_tool([sys.executable, "-c", "pass"], env={"PATH": "/usr/bin"})
        other = run_tool([sys.executable, "-c", "pass"], env={"PATH": "/bin"})
        assert base.env_digest != other.env_digest

    def test_truncation_flagged(self) -> None:
        big = "x" * 4096
        result = run_tool(
            [sys.executable, "-c", f"print('{big}')"],
            max_output_bytes=64,
        )
        assert result.truncated
        assert len(result.stdout.encode()) <= 64 + len("\n...[TRUNCATED]")

    def test_timeout_raises_typed_error(self) -> None:
        with pytest.raises(ToolTimeoutError):
            run_tool([sys.executable, "-c", "import time; time.sleep(5)"], timeout_s=0.2)

    def test_missing_binary_raises_typed_error(self) -> None:
        with pytest.raises(ToolError, match="failed to start"):
            run_tool(["definitely-not-a-real-binary-xyz"])

    def test_empty_argv_refused(self) -> None:
        with pytest.raises(ToolError, match="empty argv"):
            run_tool([])

    def test_to_row_shape(self) -> None:
        result = run_tool([sys.executable, "-c", "pass"])
        row = result.to_row(invocation_ref="step-9")
        assert row["argv_digest"] == result.argv_digest
        assert row["invocation_ref"] == "step-9"
        assert row["truncated"] in (0, 1)
