# 0024. Testing & Documentation Hardening

- **Date:** 2026-08-25
- **Status:** Accepted
- **Related:** All ADRs

## Context

Phases 1–9 introduced 10 new domain models, 3 new value objects, 2 new SQLite tables, and CLI commands. The test suite needs to cover these additions, and the integration tests need to validate the full migration chain.

## Decision

**New test modules:**
- `tests/unit/test_observations.py` — 9 tests for `ObservationLog` (emit, query, snapshot, anomalies)
- `tests/unit/test_load_strategy.py` — 9 tests for `LoadStrategy` and `FuzzStrategy` (factories, round-trips, calculations)
- `tests/unit/test_campaigns.py` — 8 tests for `Campaign` and `CampaignSchedule` (validation, sorting, round-trips)
- `tests/unit/test_network_topology.py` — 6 tests for `NetworkTopology` (segment membership, path lookup, cross-segment detection)
- `tests/unit/test_execution_context.py` — expanded with `ResourceOwnership` tests
- `tests/integration/test_store.py` — expanded with migration v3 table existence check, campaigns CRUD, and observations insert/query

**Final test count:** 304 tests, all passing.

**Documentation:**
- 24 ADRs documenting every significant architectural decision
- This final ADR closes the documentation loop

## Consequences

- Every new domain model has unit tests covering creation, validation, serialization, and query helpers.
- Integration tests verify the full migration chain from v1 to v3.
- The test suite is a safety net for future refactoring — any regression will be caught.
