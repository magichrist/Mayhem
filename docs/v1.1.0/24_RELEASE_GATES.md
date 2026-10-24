# Plan 24 — Release Gates and Definition of Done

**Priority:** P0. Meta document: the binary checklist every v1.1.0
milestone must satisfy. Enforcement phases map gates to the M1–M8
milestones in 27_IMPLEMENTATION_BACKLOG.md.

## Every release gate
### Code
- unit tests
- integration tests
- static analysis
- dependency audit
- security scan
- SBOM

### Faults
- certification matrix pass
- compensation verification
- residue scan
- compatibility matrix update

### Platform
- upgrade test
- downgrade/rollback test where supported
- controller restart
- agent restart
- database restore
- network partition test

### Evidence
- bundle generation
- offline verification
- signature verification (future-gated: blocked on
  12_CRYPTOGRAPHIC_EVIDENCE.md signing landing; until then this gate
  is recorded as NOT APPLICABLE with the reason cited, never silently
  skipped or hand-waved green)
- tamper test

### Safety
- forbidden-pair regression suite
- risk policy tests
- damage quota tests
- approval binding tests
- emergency-stop tests

### Documentation
- migration guide
- compatibility matrix
- security advisory summary
- known limitations

## Enforcement phasing
- M1 exits on the fault gates (certification, compensation, residue, matrix).
- M2 exits on the safety gates (pairs, quota, approval binding, e-stop) plus partition tests.
- M3 exits on the platform gates (upgrade, restart, restore) plus code gates.
- M5 exits on the evidence gates (offline verification, tamper; signature gate still NOT APPLICABLE until 12 lands).
- Production class additionally requires the documentation gates complete and the honesty scans (no overclaim badges, no unsigned-trust language) green.

## Release classes
- experimental
- beta
- production
- LTS

A production/LTS release cannot contain undocumented runtime gaps represented as verified capabilities.

## STATUS — gates defined and enforced on the certification pipeline; the release half is not green

The gate engine is not a plan. `domain/pipeline.blocking_reasons`,
`controller/check_gate.evaluate_pr_checks`, `controller/check_gate.release_gate`
and `controller/check_gate.proof_view_for_report` all landed, and the fault-gate
section passes on the certification pipeline itself — which was Phase 1's exit
criterion. "Enforcement begins with the first M1 lane" was true when written and
is false now: all eight M lanes have landed.

What is **not** done:

- ~~`release_gate()` has no production caller in `src/`. `--release-gate` is
  rendered into generated CI workflows by `controller/ci_surface.py:461` and
  `:568`, but nothing invoked the Python gate.~~ **Closed by
  `docs/v1.1.0/LAST/L3_RELEASE_GATE_CALLER.md`.** `mayhem ci check --release-gate`
  calls it: `cli/ci_cmd.py::_apply_release_gate` invokes
  `release_gate(verdict, request, suites=..., open_findings=...)`, so the flag
  rendered into generated CI workflows by `controller/ci_surface.py:461` and
  `:568` answers to a real gate. What remains true, and is the part that
  matters: `--release-gate` is opt-in and off by default at both the workflow
  and the check level, nothing enforces that any pipeline passes it, and no CI
  system has ever executed it — plan 16 records that: no runner, no workflow
  event, no token.
- ~~Nothing calls `release_gate(..., open_findings=...)`, so the regression-finding
  feed plan 22 Phase 4 built has no path into a release decision.~~ **Closed by
  the same caller.** `mayhem ci check` accepts repeatable `--finding PATH`
  options, rehydrates each stored finding with `RegressionFinding.from_dict`,
  and hands them to the gate as `open_findings` — plan 22's feed now has a path
  into a release decision. What remains true: without a `--run PATH` pin the
  gate invoked from this surface can only ever block, never allow, because
  `blocking_reasons` then always contains "no run is cited" — with `--run` it
  can allow — and a finding has no close/resolve state, so "open" means every
  stored finding.
- The full suite is not green for a production-class release and cannot be until
  `certified_faults > 0` (plan 01) and a soak run exists (plan 23). The gate
  reports that honestly rather than passing a release with nothing behind it:
  `certified_faults = 0` means there is no live claim to regress.
