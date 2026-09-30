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

## STATUS — planning only, 0%
Gates defined; enforcement begins with the first M1 lane.
