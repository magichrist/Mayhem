# 0022. Campaign Model

- **Date:** 2026-08-25
- **Status:** Accepted
- **Related:** [ADR-0005](0005-recovery-model-lease-journal-janitor.md) (recovery model), [ADR-0009](0009-random-experiments.md) (random experiments)

## Context

Chaos experiments run as isolated one-shots. There's no concept of scheduling multiple experiments over time, managing concurrency between them, or defining policies for what happens when one fails.

## Decision

A `Campaign` is a named, schedulable collection of experiments with execution policies:

**`CampaignExperiment`** — one entry in a campaign:
- `experiment_ref` — name or ID of the experiment spec
- `priority` — execution order (higher first)
- `delay_seconds` — gap after previous experiment
- `weight` — for weighted random selection

**`CampaignWindow`** — time constraints:
- `start_epoch_s`, `end_epoch_s` — execution window
- `max_duration_s` — hard stop
- `cooldown_between_experiments_s` — gap between experiments

**`CampaignPolicy`** — execution policies:
- `on_experiment_failure` — `abort_campaign`, `skip_and_continue`, `retry_then_abort`
- `max_concurrent_experiments` — concurrency limit (default: 1)
- `max_risk_level` — risk ceiling for all experiments
- `total_budget_usd` — cost ceiling (future use)
- `require_approval_above` — risk level requiring manual approval

**`CampaignSchedule`** — runtime state for a scheduled campaign:
- `run_count`, `next_experiment_idx`, `last_run_epoch_s`

**`Campaign`** — the top-level container:
- `status` — `draft → scheduled → running → paused → completed → aborted`
- `sorted_experiments()` — ordered by priority
- `total_weight()` — sum of all weights

All models are frozen Pydantic, JSON-serializable.

## Consequences

- Experiments can be grouped and scheduled as a coherent chaos program.
- Failure policies prevent one bad experiment from killing an entire campaign.
- Risk ceilings and approval gates enforce production safety.
- The `draft → scheduled → running → completed` lifecycle enables review workflows.
- Backward compatible: existing standalone experiments are unaffected.
