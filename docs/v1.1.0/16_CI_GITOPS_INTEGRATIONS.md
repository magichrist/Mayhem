# Plan 16 — CI/CD, GitOps, and Change Integrations

**Priority:** P1. Gap items 42, 43, 44, 45, 46, 47.

## Objective
Make Mayhem a developer workflow, not just an SRE tool: validate in pull requests, gate releases on resilience, manage experiments as code, and link every run to the change system — folding in PR resilience checks (46).

## Builds on
- Existing machine-readable commands: `prepare validate/plan`, `run --execute`, `bundle build`, `inspect` history — the CI surface composes these, never shell-scrapes prose.
- `plan_diff.py` digests, evidence bundles, and coverage cells give CI stable artifacts to assert on.
- Ticket references ride the 09 approval model (change_ticket as approval metadata, not free text).

## Integrations
GitHub Actions, GitLab CI, Jenkins, Buildkite, Argo CD, Argo
Workflows, Tekton, Terraform provider, Jira, ServiceNow, PagerDuty,
Opsgenie, Slack/Teams ChatOps.

## Git workflow
```text
experiment YAML
 -> PR
 -> validate
 -> safety proof
 -> review
 -> merge
 -> schedule/run
 -> evidence
```

## Release gate
Attach resilience suites to deployments and dependency/infrastructure changes.

## Phase 1 — Domain model: pipeline and change-link types
Add `domain/pipeline.py`: `PipelineVerdict` (pass/fail with cited run plus evidence refs), `ChangeLink` (ticket, deployment id, git SHA, plan/policy/catalog/agent/runtime version pins), `PRCheck` (check name, scope, outcome, coverage delta). Pure types; "same experiment plus new release" comparability as a pure predicate over pins. Acceptance: pin-completeness tests — a run missing any pin cannot back a release-gate decision.

## Phase 2 — Engine: check evaluation and release gating
Evaluate PR checks (syntax, target validity, safety policy, blast radius, damage budget, fault compatibility) and release gates (resilience suites on deploy, on dependency change, on infra change) through the normal compile → proof → policy path. ChatOps commands (`run`, `approve`, `stop`) dispatch through identical validation as CLI, bound to the requester's identity (09). Acceptance: a failing resilience verdict fails the pipeline; ChatOps approval from an unauthorized principal is refused.

## Phase 3 — Surface: actions, apps, provider, bots
Ship GitHub Action and GitLab component, GitHub App for PR checks (gap 46: syntax, policy, blast, budget, compatibility, plus coverage warnings like "checkout has no experiment covering PostgreSQL failure"), Terraform provider (`mayhem_experiment` resource over the 08 API), ChatOps bots with approval scoping. Acceptance: PR-check output golden-tested; Terraform plan/apply round-trips against the API in tests.

## Phase 4 — Safety and evidence integration
CI executions carry the same execution intent and approvals as interactive runs (service-account identity, never ambient privilege); every pipeline decision links the exact run evidence; ticket refs sealed into the chain. Acceptance: a pipeline run without an evidence link fails the gate closed, never open.

## Phase 5 — Tests, regression guards, negative controls
Check-evaluation tests on fixture PRs, gate tests on fixture releases (including the v2.4→v2.5 tolerance-regression example), ChatOps authorization tests, Terraform conformance tests. Negative controls: a PR check that cannot reach the control plane reports unknown, never pass; a merged plan that differs from the checked plan invalidates prior approvals. Acceptance: full matrix green.

## Phase 6 — Docs, honesty gates, rollout
CI cookbook per provider, GitOps reference architecture, ChatOps command reference with authorization matrix. Rollout: validate-in-PR first, release gates second, ChatOps and Terraform last. Acceptance: no doc suggests gating production on uncertified faults (ties to 01 states).

## Dependencies
07 (policy evaluation in checks), 08 (API backing), 09 (identities, approvals, ticket refs), 12 (evidence links), 22 (coverage deltas), 30 (proof in PR).

## STATUS
- Phase 1 (domain model): DONE — `domain/pipeline.py` landed `PipelineVerdict` (pass/fail with a required non-empty `evidence_refs` and a construction-time refusal of a pass over any non-passing check), `ChangeLink` + `PipelinePins` (ticket/incident/deployment/git SHA plus the five plan/policy/catalog/agent/runtime axes, blank-able so the gate refusal is testable), `PRCheck` (name/scope/outcome/coverage delta/structured finding, fail-closed — an unreachable control plane may only report `UNKNOWN`), `CoverageDelta` over `CoverageCell`, `PlanApproval`/`PlanMerge` for invalidation on plan change, and the pure predicates `gates_release`/`blocking_reasons`/`comparable_across_release`; 80 tests.
- Phase 2: not started
- Phase 3: not started
- Phase 4: not started
- Phase 5: not started
- Phase 6: not started

Overall: 1 of 6 phases complete.
