# Plan 09 — Campaigns, Coverage, and Explore Loop

## Builder brief

Turn `campaign`, `coverage`, `next`, and `explore` into one coherent resilience-engineering loop. Today these commands are powerful but fragmented: users must understand which data is stored, how candidates are ranked, what a blocked cell means, and how a campaign relates to individual runs.

## Phase 1 — Unify the candidate and coverage model

### Work

- Define a `ResilienceCell` record with target, failure domain, fault, engine, risk, maturity, state, last run, and next rationale.
- Make `coverage`, `next`, and `explore` consume the same repository and ranking service.
- Add filters for target profile, engine, service, failure domain, risk, maturity, and state.
- Make coverage state transitions explicit: unknown, planned, executed, passed, inconclusive, failed, blocked, skipped.
- Add stable JSON output for all cell queries.

### Files

- `src/mayhem/domain/coverage.py`
- `src/mayhem/infra/coverage_repository.py`
- `src/mayhem/infra/ranking.py`
- `src/mayhem/controller/explore_flow.py`
- `src/mayhem/cli/coverage_cmd.py`
- `src/mayhem/cli/next_cmd.py`
- `tests/unit/test_coverage.py`
- `tests/unit/test_ranking.py`

### Verification

- Unit tests prove identical inputs produce identical rankings and state transitions.
- Human and JSON output use the same cell data.
- No command invents a separate coverage vocabulary.

## Phase 2 — Redesign campaign lifecycle

### Work

- Define campaign states: draft, approved, running, paused, completed, aborted, archived.
- Add pause/resume only after state transitions are persisted and tested.
- Add campaign target profiles, engine policy, budget, deadline, and stop conditions.
- Add dry-run campaign planning with an execution manifest.
- Link campaign cells to runs, plans, evidence, and verdicts.
- Keep current create/list/show/status/start/run/abort/archive/delete aliases.

### Files

- `src/mayhem/domain/campaigns.py`
- `src/mayhem/domain/m5_campaign.py`
- `src/mayhem/infra/campaign_engine.py`
- `src/mayhem/cli/campaign.py`
- `tests/unit/test_campaigns.py`
- `tests/unit/test_campaign_run.py`

### Verification

- State transition tests cover every allowed and forbidden edge.
- Campaign dry run is side-effect free.
- Existing campaign commands preserve exit codes and JSON fields.

## Phase 3 — Add the unified operator loop

### Work

- Add a `coverage next` view that explains why a cell was selected.
- Add `explore --plan-only` and `explore --execute` separation.
- Add campaign resume after interruption with explicit recovery status.
- Add run-level links back to campaign and coverage cell.
- Add a concise operator summary: coverage delta, blocked cells, highest-risk gaps, and next recommended action.

### Acceptance criteria

- A user can move from coverage gap to safe plan to run evidence without switching mental models.
- A campaign is explainable and resumable without hidden state.
- Explore never mutates a target when the user requested a plan-only view.

### Verification

- Run campaign, coverage, ranking, explore, CLI, documentation, and full unit tests.
- Run Ruff and keep external runtime validation out of automated checks.
