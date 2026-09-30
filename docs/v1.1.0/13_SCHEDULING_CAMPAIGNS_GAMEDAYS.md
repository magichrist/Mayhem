# Plan 13 — Scheduling, Campaigns, and Game Days

**Priority:** P1. Gap items 41, 48, 84, 85.

## Objective
Run experiments on schedules, group them into campaigns with shared budgets, and turn game days into evidence-producing operations — folding in scheduling fairness (84) and the experiment concurrency model (85).

## Builds on
- `infra/campaign_engine.py`, `domain/campaigns.py` (DRAFT → … → ARCHIVED), `domain/campaign_checkpoint.py`, `domain/m5_campaign.py` stay the campaign core — scheduling and fairness extend them, never replace them.
- `domain/game_day.py` sessions (separate table from campaigns by design) stay the game-day core.
- Existing gap, closed here: the campaign CLI does not expose scheduling. That absence is this plan's Phase 3.

## Scheduling
Cron, intervals, timezone-aware calendars, business hours, maintenance
windows, blackout dates, deployment-aware and incident-aware
scheduling (07 state inputs), concurrency policy, priorities, jitter.

## Campaigns
A campaign groups experiments with shared budget, policy, environment,
objective, approval, and evidence.

## Game Days
Facilitator, participants, scenario, timed injects, observations,
operator decisions, notes, findings, after-action report.

## Phase 1 — Domain model: schedules, fairness, concurrency
Add `domain/scheduling.py`: `Schedule` (cron/interval/calendar/window/blackout rules, timezone), `FairnessPolicy` (per-team shares, starvation prevention for gap 84), `ConcurrencyClass` (`parallel | exclusive | shared-resource | conflicting | preemptible` for gap 85) with a lock-compatibility matrix over resource locks (07). Pure types; "two exclusive experiments on one database → second queues naming the first" as a pure scheduling predicate. Acceptance: fairness simulation tests (no team starves over N windows); compatibility-matrix tests.

## Phase 2 — Engine: durable scheduler over the campaign engine
Scheduler service evaluates due schedules against policy windows, blackouts, deployment/incident state, budgets, and fairness shares; dispatches through normal plan → approve → execute flow (scheduled runs are never exempt from gates); persists schedule state in the store so recurring runs survive controller restarts (with 08 replication). Game-day injects dispatch as scheduled steps with facilitator holds. Acceptance: controller-kill mid-schedule resumes without double-firing (idempotency keys from 03).

## Phase 3 — Surface: schedule and game-day commands
Expose scheduling on the campaign surface (closing the known gap), plus game-day facilitation commands (create, approve, start, pause, inject, note, complete — extending the existing game-day command group). Acceptance: every new invocation resolves against the live Click tree; the release contract stays green.

## Phase 4 — Safety and evidence integration
Scheduled runs honor policy and blackout windows at fire time, not just at creation (windows are evaluated live); game-day artifacts (decisions, notes, findings) become normal evidence objects feeding the after-action report; campaign budgets enforced hierarchically via 07. Acceptance: a schedule whose window closed between creation and fire time does not fire, with the non-fire recorded.

## Phase 5 — Tests, regression guards, negative controls
Schedule-evaluation tests ( DST boundaries, blackout overlaps, jitter bounds), fairness tests, concurrency tests (conflicting experiments serialize with named owners), game-day evidence tests. Negative controls: a schedule firing during an active incident without commander override is refused; a game-day inject outside its scenario is refused. Acceptance: full matrix green; restart-recovery drill in CI.

## Phase 6 — Docs, honesty gates, rollout
Scheduling reference (cron dialect, timezone rules), campaign operations guide, game-day facilitation guide with report template. Rollout: manual game days first, interval schedules second, cron plus fairness last. Acceptance: no doc promises schedule precision the engine does not bound.

## Dependencies
03 (idempotent dispatch), 07 (windows, budgets, locks), 08 (durable state, replication), 09 (approvals for campaigns), 12 (game-day evidence).

## STATUS — planning only, 0%
