# Toolkit architecture reference

`src/mayhem/config.py` exposes `toolkit.binaries` as explicit binary overrides. `src/mayhem/toolkit/registry.py` resolves the configured or manifest-provided binary, and `src/mayhem/toolkit/tool_runner.py` executes it with bounded output, timeout, and redacted result evidence.

Tool availability is execution-time state. A catalog definition can be valid while its binary or capability is unavailable; the safety and executor layers must refuse rather than claim success.
