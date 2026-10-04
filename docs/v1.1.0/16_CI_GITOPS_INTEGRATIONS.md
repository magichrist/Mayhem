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
- Phase 2 (engine): DONE — `controller/check_gate.py` evaluates the six PR checks by projecting one `compile_safety_evidence` run onto them (no check re-derives a gate), gates releases on resilience suites attached to deployments/dependency/infra changes and fails closed, states every coverage number as `N of M`, and dispatches ChatOps `run`/`approve`/`stop` through an injected validator behind an identity gate; 92 tests.
- Phase 3 (surface): DONE — `controller/ci_surface.py` (pinned GitHub Actions and GitLab CI generators that refuse a floating action tag, a floating image, and any untrusted value carrying shell syntax; the PR-check summary renderer; the unbound `CommitStatusPort` and the four-way `UNREACHABLE` collapse), `controller/chatops.py` (channel bindings out of band, an unbound-channel default-deny scope, message-is-data parsing, and uniform `REFUSED` outcomes), `controller/terraform_provider.py` (the `mayhem_experiment` resource over plan 08's API, with unreadable-is-not-absent, refuse-on-plan-stale, and refuse-on-unconfirmed-write), and `cli/ci_cmd.py` (`mayhem ci workflow|check|summary|status`, exiting non-zero whenever any check did not pass). LANDED AFTER THE PASS ABOVE: the `ci` group is registered on the live CLI tree (`cli/command_registry.py`), so `mayhem ci --help` resolves and all four subcommands are reachable by name; the registration is asserted against the real Click tree and against the three inventories by `tests/unit/test_ci_registration.py`, and the reachable surface is enumerated leaf-by-leaf in `tests/unit/test_cli_exhaustive_matrix.py`. Registration adds reachability only — it claims no workflow has run. Jenkins, Buildkite, Argo Workflows, and Tekton are named in the plan and deliberately not implemented (closed `Provider` vocabulary of `github`/`gitlab`, stated rather than guessed). Fixes made this pass: a duplicated `--rm` in the emitted container command line, a GitLab component that dropped the spec's `--check`/`--release-gate` flags and silently ignored pinned actions, `parse_command`'s "never raises" docstring, dead constants, and an inverted guard in `ci_cmd.check_cmd` that fired when everything *passed*. 165 tests across `test_ci_surface.py` (54), `test_terraform_provider.py` (45), `test_chatops.py` (44), `test_ci_surface_cli.py` (23).
- Phase 4 (safety/evidence): DONE — `controller/ci_execution.py` landed `CIActor` (a declared service-account or workload identity; a human principal is refused as ambient privilege at construction, an ungranted actor at role resolution), `seal_ticket`/`SealedTicket` (change references bound to a digest, verified against a caller-supplied check-time seal, and `seal_verified` recording whether the check could have failed), `link_run_evidence` (four refusals: no cited run, no envelope, an envelope for another run, an envelope whose digest is not the pin's), and `pipeline_run_authorization`, which delegates to `domain.execution_intent.require_execution_intent` rather than writing a second approval gate. NOT LANDED / NOT CLAIMED: no CI system has ever executed this code — no runner, no workflow event, no token, and no environment variable in the module's signature that mayhem reads on its own. 52 tests in `test_ci_execution.py`.
- Phase 5 (tests, regression guards, negative controls): DONE — `tests/unit/test_ci_pipeline_gates.py` runs whole-plan check evaluations over a fixture-PR matrix (each fixture tripping a different check), the plan's own v2.4 → v2.5 tolerance-regression worked example end to end (compare → `ResilienceSuite` → `release_gate`), and eight named negative controls. `test_ci_execution.py` adds three more. Each control breaks its property *on purpose* and asserts the break is observable: stubbing `_unreachable_report` makes all-`PASS` checks constructible behind an unreachable plane; stubbing `PlanMerge.changed` restores the approvals and re-opens the gate; `model_construct` on `ReleaseGateDecision` builds the evidence-free allow the constructor refuses; stubbing `CIActor.require_role` admits an ungranted pipeline; stubbing `effective_roles` lets an unauthorized approver reach validation; `PRCheck.model_construct` bypasses the unreachable-may-only-be-`UNKNOWN` guard; monkeypatching `CIActor.__post_init__` admits a human principal; and `PlanApproval` bound to the merged digest still invalidates when the plan moved. 69 tests in `test_ci_pipeline_gates.py`.
- Phase 6 (docs, honesty gates, rollout): DONE — `docs/v1.1.0/16_ci_cookbook.md` (per-provider cookbook, what-is-generated-versus-only-validated table, the pinning and containment rules, the release-gate trigger table, the Phase 4 admission rules, the rollout order) and `docs/v1.1.0/16_gitops_reference.md` (the Terraform resource, the three API reach states, refuse-on-drift, the ChatOps command reference with an authorization matrix rendered from the engine's own table, and the honesty gates). NOT LANDED / NOT CLAIMED: no workflow has run on a forge, no Slack or Teams client exists, no `terraform` binary has been driven, no pack signature is ever verified (a pack is integrity-checked by content digest and carries **no public key**, so nothing authenticates its author) and `verified-live` stays 0. The docs are asserted against source by `tests/unit/test_ci_plan_docs.py` (17 tests) rather than reviewed by eye — including that the authorization matrix in the prose is the engine's table, that the cookbook quotes the real pinned SHA, that every user-reachable refusal code is documented, and Phase 6's own negative criterion that neither document suggests gating production on uncertified faults.

Overall: 6 of 6 phases complete.
