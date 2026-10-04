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

## Phase 6 deliverables — the reference, in this file

### Cron dialect

Five fields, wall-clock, no seconds: `minute hour day-of-month month day-of-week`.
`*`, `n`, `a-b`, comma-separated lists of those, and `/step` on any of them;
`@hourly` / `@daily` / `@weekly` / `@monthly` / `@yearly` nicknames; three-letter
month and weekday aliases. Day-of-week is 0-6 with Sunday = 0, and 7 is accepted
as Sunday and folded onto 0. When **both** day-of-month and day-of-week are
restricted the match is a **union**, matching Vixie cron: `0 0 1 * MON` fires on
the first of the month *or* on any Monday.

Six- and seven-field expressions are **refused** with
`schedule.cron_field_count`, not guessed at. A scheduler that accepted a
six-field expression and assumed the sixth field was a year would fire at the
wrong time, which is the one failure this module exists to prevent. An
impossible calendar such as `0 0 30 2 *` answers "no future occurrence" in
bounded time rather than hanging.

### Timezone rules

A schedule carries one IANA zone (`--timezone`, default `UTC`) and an unknown
zone is refused by name with `schedule.unknown_timezone`.

* **Cron is evaluated on the schedule's own wall clock.** A wall clock the zone
  *skipped* (the spring-forward gap, where `02:30` names no instant of the year)
  contributes no occurrence; a wall clock that *happens twice* (the fall-back
  hour) contributes only its first occurrence, so a `01:30` cron fires once and
  not twice.
* **Intervals are absolute, not wall-clock.** Occurrences are `anchor + n *
  every_s`, so a periodic schedule keeps its period across a DST transition
  instead of drifting by an hour twice a year.
* **Business hours and blackout dates are local dates.** "The 4th is blacked out"
  means the 4th where the schedule runs.
* **Every stored instant is aware.** A naive `--anchor-at`, `--now`, or `--created-at`
  is a usage error; a schedule whose anchor says "09:00" with no zone is a
  schedule whose fire time depends on which machine reads it.

### What the scheduler does not promise

* **No precision claim.** A cron slot stays open for one minute and an interval
  slot for `poll_resolution_s`; a poller that arrives later gets a *missed
  window*, reported as `schedule.missed` with the missed instant named, not a
  fire that pretends to be on time. `--jitter-s` moves a fire time by a bounded,
  hash-derived offset, and the payload reports `nominal_at` and `effective_at`
  separately so the bound is visible rather than asserted.
* **No second concurrency cap.** The enforced concurrent-fault budget is
  `blast_radius.max_concurrent_faults`, read by `controller.safety.validate_plan`.
  `config.max_faults` is deprecated and enforces nothing, and this plan does not
  reintroduce it. `ConcurrencyClass` and the lock matrix are about *resource*
  serialisation between runs, which is a different question from how many faults
  one plan may inject.
* **No live-cluster claim.** `mayhem schedule tick` reads the local SQLite
  registry and says which of three gates it did not evaluate: the safety gate,
  the approval gate, and the concurrency model. A due slot is not an admitted
  slot, and the payload carries that sentence.
* **No signature verification, no attestation.** Nothing in this plan verifies a
  pack signature or promotes `verified-live`.

### Campaign operations

A campaign groups experiments under one budget, policy, environment and
objective. A schedule is the *trigger* for one experiment inside it; the campaign
owns the objective, the schedule owns only the recurrence.

Dispatch order within a window is the fairness policy's, not registration order.
`FairnessPolicy` gives each team a relative weight and, once a team has been
skipped for `starvation_window` consecutive windows, an absolute priority
regardless of weight, longest-waiting first inside that tier. The guarantee is a
property of `select_team` and it is checked by *removing* the starvation tier and
watching the bound break, not by restating it.

Budgets are 07's damage hierarchy — team → environment → service → experiment →
fault — and `campaign_budget_verdict` probes it without spending: a charge posts
to the leaf *and every ancestor*, and an exhausted ancestor refuses even when the
leaf has headroom. No mounted campaign budget is allowed rather than refused; a
*malformed* one refuses, because a charge nobody is accountable for is not a
budget.

### Game-day facilitation, and the report template

`mayhem game-day-step inject` stages a scheduled dispatch as a **held** step;
there is no flag that stages one already released, because a hold that exists
only to be immediately bypassed is not a hold. `release` names the facilitator
and the reason; `hold` re-holds and leaves the release on the record; `note`
records an artifact. A step's `--scenario` must resolve against plan 21's
`SCENARIO_TEMPLATES` in the library's own `id@version` spelling.

Three artifact kinds, enforced rather than documented: a **decision** names a
run, a **note** carries nothing but an actor and a text, and only a **finding**
may carry a severity. A severity on a note is *refused*, not stripped — a record
written as `info` that reads back ungraded is one whose grade nobody chose.

The after-action report has a fixed template, because the sections that are empty
are the ones carrying information. Four gaps are named rather than elided:

| gap | what it means |
| --- | --- |
| `released_without_decision` | a drill was let go and nobody wrote down why |
| `failed_dispatch` | a slot settled `failed`; the drill did not complete |
| `unknown_outcome_dispatch` | a claim was never settled, so whether it ran is unknown |
| `no_findings` | nothing was claimed wrong — **not** a clean bill of health |
| `no_artifacts` | the session produced nothing at all |

```text
# After-action report: <session>
_assembled <instant>

## What ran
- `<step_id>` (<scenario>) -> <schedule_id>: <hold_state>, released by <who>

## Dispatches
- <slot> <schedule_id>: <state> (<code>)

## Findings
- **<severity>** — <text> (<actor>)

## Notes
- <text> (<actor>)

## Decisions
- <text> (<actor>, run <run_id>)

## Gaps
- **<gap>** — <what a facilitator should do about it>
```

An empty `## Findings` renders as: *"**none recorded.** That is a statement about
this report, not about the system."*

### Rollout

1. **Manual game days first.** A facilitator stages steps by hand and releases
   them by hand; nothing fires on a clock, so the first thing exercised is the
   vocabulary and the report.
2. **Interval schedules second.** A fixed period with an anchor and an explicit
   `poll_resolution_s` is the smallest recurrence whose slots and idempotency keys
   are easy to reason about by hand.
3. **Cron plus fairness last.** Both depend on the two above having been read in
   production before they are relied on, and fairness is a policy choice that is
   only safe once the operator can see who won the last window.

## STATUS
- Phase 1 (domain model): DONE — `domain/scheduling.py` lands `Schedule` (5-field cron / interval / calendar + business hours, maintenance windows, blackouts, bounded deterministic jitter), `FairnessPolicy` (weighted shares with a provable anti-starvation floor), and `ConcurrencyClass` with a symmetric lock-compatibility matrix over 07's `ResourceLock`; every decision is a pure function of an injected instant. Extended in this lane: jitter is applied to the **slot** rather than to the evaluation instant, `FireDecision` grew `nominal_at`/`resolution_s`, `lateness_s` reports *poller* lateness (`now - nominal_at`) rather than the jitter offset, `jittered` compares against the nominal so an unjittered late poll and a calendar window both stop reading as jittered, and a new `FireCode.MISSED` distinguishes a recurrence whose slot closed from an ordinary quiet instant
- Phase 2 (engine): DONE — `controller/scheduler.py` + `infra/schedule_store.py` land a durable scheduler that evaluates registered schedules at fire time, orders dispatches by the fairness policy, refuses on incident/deployment/hold/concurrency state, and dispatches through a four-stage pipeline whose planner, admission, approver, and executor are all required; `M0026_SCHEDULES` persists the registry, the claim ledger keyed by a slot-derived idempotency key (the no-double-fire mechanism, enforced by a primary key), and game-day dispatch steps whose facilitator hold is read at fire time. Extended in this lane: `PlannedDispatch.dispatch` carries the shared compilation forward so the admission gate judges *that* proof, and defaults to `None` — which the campaign binding treats as **no proof at all** and refuses
- Phase 3 (surface): DONE — `cli/schedule_cmd.py` (add / list / show / next / tick / runs / fairness / enable / disable / delete) and a new `cli/game_day_step_cmd.py` (inject / steps / hold / release / note). Every invocation in each module's `MONITORED_INVOCATIONS` is resolved against the live Click tree by `tests/unit/test_game_day_dispatch.py`. Neither group is registered in `cli/app.py` or `cli/command_registry.py` — see the integration list below. Neither group carries a flag that dispatches, asserted over the AST
- Phase 4 (safety and evidence): DONE — `controller/campaign_dispatch.py` lands the **one** shared compile → proof → policy core (`compile_campaign_run`, no origin parameter, no branch), `build_dispatch_pipeline` binds the scheduler's four required stages to the real `validate_plan` / `verify_approvals` / executor, and `campaign_budget_verdict` probes 07's damage hierarchy without spending it. `controller/game_day_evidence.py` lands the artifact vocabulary, the single observation writer, and `after_action_report` with its five named gaps. Windows are read live at fire time and a missed recurrence is recorded as `schedule.missed`. Two new rule ids (`schedule.campaign_budget`, `schedule.no_compilation`) are raised only by this module, which is not one of the two gate modules `OBLIGATION_FOR_RULE` / `RULE_CHECK` describe
- Phase 5 (tests and negative controls): DONE — 388 tests green across `tests/unit/test_scheduling.py` (155), `test_scheduler.py` (72), `test_campaign_dispatch.py` (24, new), `test_game_day_dispatch.py` (56, new), and the pre-existing campaign/game-day files. Negative controls, each breaking a named property: a poller that slept through a recurrence gets `schedule.missed` and never a fire; a cron slot can never report a miss; a quiet instant before the anchor is never dressed up as one; a jitter spread is never read as poller lateness; `VOID` is refused and the unestablished line is named; a plan with no compilation is refused by rule id; a budget probe spends nothing on the caller's tree; an artifact with a severity on a note is refused rather than stripped; a report with no findings is never `clean`; an inject against an unknown scenario writes nothing; and neither surface names a dispatching flag or symbol
- Phase 6 (docs and rollout): DONE — the cron dialect, timezone rules, campaign operations guide, game-day facilitation guide with the report template, and the three-step rollout are written above. No document here promises schedule precision the engine does not bound

### Integration dependencies this lane could not satisfy

Items (1), (3) and (4) are still edits to files other lanes own, and none is
worked around. Item (2) was reported here rather than assumed safe, and has since
been closed by a later wave — recorded below rather than deleted, because the
report was the honest state at the time this lane shipped.

1. **`cli/app.py` + `cli/command_registry.py`** — both groups need a
   `CommandSpec` row and a `command_map` entry before `mayhem schedule --help`
   and `mayhem game-day-step --help` resolve from the root command. Suggested:
   `CommandSpec("schedule", "campaign", help_group="campaign", mutating=True)` and
   `CommandSpec("game-day-step", "game-day", help_group="campaign", mutating=True)`;
   `command_map["schedule"] = schedule` from `mayhem.cli.schedule_cmd` and
   `command_map["game-day-step"] = game_day_step` from
   `mayhem.cli.game_day_step_cmd`. `help_group` and `mutating` are guesses and
   belong to whoever owns the inventory. **Not wired.**
2. **`tests/unit/test_evidence_boundary.py::BOUNDARY_CALL_SITES`** — **RESOLVED,
   after this lane shipped.** As reported at the time:
   `controller/game_day_evidence.py::record_artifact` writes through
   `Store.save_observation`, the same surface
   `infra/schedule_store.py::ScheduleStore.record_tick` uses, and **neither call
   site was inside the secret boundary**. That was a real gap, stated rather than
   assumed: a facilitator's free-text note is operator-authored and could carry
   anything. The row that would close it was
   `("mayhem.infra.store", "Store.save_observation") -> {"require_persistable_document"}`
   — one row for both writers, which is the honest granularity because they are
   one function. Registering only this lane's caller would have left
   `record_tick` outside the boundary while the table claimed to cover
   `save_observation`.

   That row is now in `BOUNDARY_CALL_SITES`, and
   `mayhem/infra/store.py::Store.save_observation` calls
   `require_persistable_document` on `data` **before** the write transaction
   opens — a refusal therefore leaves no row rather than a rolled-back one, and
   `tests/unit/test_store_observation_boundary.py` asserts that ordering directly
   by counting opened transaction boundaries. **Both writers are covered by that
   one gate**, and neither `record_artifact` nor `record_tick` was edited to make
   the coverage true: the tests drive both call sites and both are refused.
   Because the gate lives in the shared function, the four pre-existing
   `save_observation` callers outside this lane (`cli/stop_cmd.py`'s four stop
   recorders, `cli/campaign.py`'s two campaign rows, `cli/services.py`'s campaign
   window rows) are inside the boundary as well — not by intent, but because they
   are the same function, which is the same reason one row is the right count.

   Still not claimed: an observation row is still not an attested, sealed or
   signed evidence row (see "No migration for artifacts" below), so this closes
   the *secret* boundary only.
3. **`tests/unit/test_command_inventory.py`** and the two sibling CLI matrix
   suites — they enumerate `COMMAND_SPECS`, so they gain rows only once (1) lands.
   **Not wired.**
4. **Plan 10's emergency stop** — a running scheduled campaign is reachable by run
   id, and `mayhem stop RUN_ID` already reaches a run by id, so the surface needs
   no change; what it *does* need is the reverse direction. Nothing tells the stop
   engine that a scheduled campaign has live claims, so a stop that freezes
   dispatch leaves the claim ledger holding `claimed` rows with no settlement.
   The seam is `StopExecution` in `controller/stop_engine.py` (not this lane's);
   the scheduler already refuses to retry such a slot, so the failure mode is a
   stale ledger rather than a double fire, and an operator resolves it. **Not
   wired.**

### What was deliberately not done

* **No wiring into `mayhem campaign run`.** `cli/campaign.py` builds its own
  `plan_from_spec` path, and routing it through `compile_campaign_run` would mean
  editing a file other lanes own. The shared core exists and is the only binding
  this plan ships; whether the campaign CLI adopts it is an integration decision,
  and until it does, "every campaign takes the identical path" is true of the
  *scheduler's* dispatches and asserted nowhere else.
* **No migration for artifacts.** They are observations, which is the surface the
  tick report already used. A dedicated table with a facilitator-facing index is
  a later change and would need a reserved id — this lane reserved none, and
  34/35 were already spoken for.
* **No `verified-live` promotion, no signature verification.** Neither is touched
  by anything in this plan.

Overall: 6 of 6 phases complete.
