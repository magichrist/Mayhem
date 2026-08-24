"""Stable, documented CLI exit codes.

Every failure category has its own number so scripts and CI can react
precisely. The mapping is part of mayhem's public contract; never reuse a
number for a different meaning. Documented in docs/reference/cli.md.
"""

from __future__ import annotations

from enum import IntEnum


class ExitCode(IntEnum):
    SUCCESS = 0
    GENERAL_FAILURE = 1  # anything not covered below
    USAGE_ERROR = 2  # bad flags/arguments (Click's native usage error)
    CONFIG_ERROR = 3  # configuration layering/validation failed
    VALIDATION_ERROR = 4  # experiment/spec/target validation failed
    SAFETY_REFUSAL = 5  # a safety gate refused the operation
    EXPERIMENT_FAILURE = 6  # experiment ran and did not complete
    RECOVERY_FAILURE = 7  # recovery/janitor left dirty state behind
    AGENT_ERROR = 8  # agent transport/runtime failure
    TOOLKIT_ERROR = 9  # external tool invocation failed structurally
    AMBIGUOUS_COMMAND = 10  # command prefix matched multiple commands
