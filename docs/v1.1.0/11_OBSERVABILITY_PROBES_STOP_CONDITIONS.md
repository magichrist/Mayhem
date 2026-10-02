# Plan 11 — Observability, Probes, and Stop Conditions

**Priority:** P0. Gap items 14, 15.

## Objective
Make Mayhem observability-native: richer probes, provider-neutral metric observations, and continuous stop conditions with real enforcement teeth (10 owns the teeth; this plan owns the definitions).

## Builds on
- `domain/steady_state.py` (Phase pre/during/post, AssertionVerb, graded Verdict with first-class `no-effect`) and the steady-state evaluator stay the verdict core; new tolerance types extend it, never fork it.
- `observability/` read-only connectors (Prometheus, Loki, OTel sink with redaction) stay the integration pattern: bounded timeouts, response-size limits, redaction before evidence.
- `providers/observation.py` read-only observation providers stay the extension point for Datadog/New Relic/Elastic/CloudWatch-class integrations.
- `domain/observations.py` SLO criteria stay the threshold vocabulary.

## Probe families
HTTP/HTTPS, TCP/UDP, DNS, gRPC, SQL, Redis, Kafka/RabbitMQ/NATS,
process, file, command, Prometheus metrics, OpenTelemetry, logs,
traces, Kubernetes state, synthetic business transaction.

## Probe lifecycle
Pre-baseline, warm-up, during fault, continuous, after recovery, final
verification. Warm-up and cooldown exist so noise is budgeted, not
discovered mid-verdict.

## Tolerances
First-class tolerance types: absolute, percentage, range, ratio,
percentile, boolean, categorical, time-to-recovery. Each type defines
its comparison function once; the evaluator and the stop-condition
engine share it.

## Stop conditions
AND/OR expressions, hysteresis, consecutive samples, debounce,
cooldown, maximum observation duration. A firing condition names the
samples that fired it — a stop without cited samples is a defect.

## Phase 1 — Domain model: probes, tolerances, conditions
Add `domain/probes.py` extensions (new families as data: endpoints, queries, sampling cadence, lifecycle membership) and `domain/stop_conditions.py` (`Condition` expression tree, `Firing` with cited samples, debounce/hysteresis parameters). Pure types with evaluation over recorded observations only — conditions never execute IO. Acceptance: expression-tree tests including hysteresis edge cases and debounce counting.

## Phase 2 — Engine: collectors and continuous evaluation
Extend `controller/observability_collector.py` (best-effort, bounded collection stays the rule: a failing source records a failed collection, never raises) with new source kinds; the stop-condition evaluator runs on the observation stream and feeds the 10 stop path. Probe definitions versioned and pinned into the plan. Acceptance: a breached condition stops a run before nominal fault duration in live-cell tests.

## Phase 3 — Surface: probe builders and integrations
Native integrations (Prometheus, OTel, Grafana read paths, Datadog, New Relic, Elastic, Loki, Tempo/Jaeger, OpenSearch, CloudWatch, Azure Monitor, GCP Monitoring, PagerDuty/Opsgenie signal inputs) as read-only connectors honoring the timeout/size/redaction contract. Probe-builder UX in CLI/UI. Acceptance: each integration ships with a fixture-backed test proving bounded, redacted behavior.

## Phase 4 — Safety and evidence integration
Probe observations enter the envelope with provenance and redaction applied; verdicts cite the exact observations that caused them; condition definitions and versions sealed with the run. Synthetic-transaction probes (multi-step customer workflows) evaluate business correctness, not just status codes. Acceptance: a verdict whose cited observations cannot be found in evidence fails verification.

## Phase 5 — Tests, regression guards, negative controls
Tolerance-type comparison tests (including the sign-blindness regression class), condition-firing tests with crafted observation streams, collector failure-mode tests (source down → failed collection, run continues or stops per policy, never hangs). Negative controls: a condition referencing an unpinned probe version is refused; a probe whose collection failed throughout cannot support a passing verdict. Acceptance: full matrix green.

## Phase 6 — Docs, honesty gates, rollout
Probe catalogue, tolerance-type reference, condition authoring guide. Rollout: metric/log families first, trace and synthetic families second, third-party integrations third. Acceptance: no doc claims an integration proves more than its provenance states.

## Dependencies
10 (stop enforcement), 12 (sealed observations), 14 (topology-linked probes), 30 (proof cites conditions).

## STATUS
- Phase 1 (domain model): DONE — `domain/stop_conditions.py`: the `Condition` expression tree (AND/OR over metric references, per-node hysteresis, consecutive-sample count, debounce, cooldown, max observation duration), `Firing` with mandatory cited samples, and tolerance types that delegate to the steady-state verdict core, all covered by `tests/unit/test_stop_conditions.py`; `domain/probes.py`: the eighteen probe families as data (endpoint / query / argv / path / target / steps, sampling cadence, window, expected unit), lifecycle membership in the plan's six stages anchored to the existing `pre`/`during`/`post` phases, warm-up and cooldown as declared budgets (a settling stage with no budget, or a budget with no settling stage, is refused), version + content-fingerprint pinning via `ProbePin`/`ProbePlan`/`ProbeCatalog` with drift refused three ways (unpinned, version drift, definition drift), and unit-mismatch refusal on any reading, all covered by `tests/unit/test_probes.py`.
- **Categorical tolerance: still absent, and that is the decision.** `ToleranceKind` carries four mechanisms; the fifth cannot be added without a non-numeric value on `ObservationResult` (`value: float | None`, no label/enum/string field), and adding one is a change to a contract every observation provider already satisfies — so it is recorded here rather than invented. The gap is enforceable rather than merely documented: `ProbeValueKind.CATEGORICAL` exists so an author can *declare* a categorical probe and be refused with `probes.categorical_unsupported`, naming the missing field. Lift the refusal in the same commit that adds the value; `tests/unit/test_probes.py::TestCategoricalIsRefusedDeliberately::test_the_refusals_precondition_still_holds` fails the moment a label-like field appears on `ObservationResult`, so the refusal cannot rot into a claim that something cannot exist.
- Phase 2: not started
- Phase 3: not started
- Phase 4: not started
- Phase 5: not started
- Phase 6: not started

Overall: 1 of 6 phases complete.
