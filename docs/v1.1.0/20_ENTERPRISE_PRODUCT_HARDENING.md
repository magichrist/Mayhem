# Plan 20 — Enterprise and Commercial Readiness

**Priority:** P1/P2. Gap items 39, 55, 56, 58, 70, 71, 77, 78, 110.

## Objective
Package Mayhem as a deployable, demonstrable, supportable product: deployment models, sandbox and demo modes, enterprise networking, reporting inputs, compliance mappings, failure-mode taxonomy — folding in the sandbox (70), demo/training mode (71), enterprise network support (77), i18n/a11y (78), and the failure-mode library (55).

## Builds on
- 08 (control plane, API, UI), 09 (organizations, teams, environments), 12 (reports over sealed evidence), 22 (coverage inputs to reports), 28 (run checklist as the operator spine).
- The honesty rule for compliance packs (below) is load-bearing for the whole program's credibility.

## Deployment models
1. Local CLI. 2. Self-hosted Kubernetes. 3. Managed/SaaS. 4. Air-gapped enterprise (offline bundle import/export per 77; verification without Mayhem installed per 12).

## Enterprise features
Organizations, projects, environments, teams, quotas, retention,
backups, support bundles, diagnostics, upgrade channels, feature
flags, audit export.

## Sandbox and demo (gaps 70, 71)
`mayhem sandbox` deploys a built-in test environment (frontend, API,
database, cache, queue, observability) for safe first runs and game-day
rehearsal; demo/training mode (safe-demo, training, simulation,
production) runs the full UX with mutation detached by construction —
simulation is the 14 simulate path wearing a friendlier face, and a
training run can never become a production run by flag drift.

## Enterprise network (gap 77)
HTTP/HTTPS proxy support, custom CA bundles, private registries and
Git, air-gapped mode, outbound allowlists. Every external call honors
proxy/CA configuration or fails closed with the cause named.

## Failure-mode library (gap 55)
Standardized taxonomy (availability, latency, correctness, capacity,
consistency, durability, partition, dependency, security-control,
resource exhaustion, clock, storage, network, process, runtime,
infrastructure, cloud, human/operator) with every catalog fault mapped
to failure mode, mechanism, expected symptom, risk, recovery, and
verification — the backbone of enterprise reporting.

## Reporting (gap 58 inputs)
Experiment, executive, audit, service-resilience, coverage, and game-day
report inputs computed from sealed evidence (rendering formats in 34).

## Compliance packs
Provide templates/evidence mappings for customer compliance programs. Do not claim compliance solely because a template exists.

## i18n and accessibility (gap 78)
CLI and UI strings externalized; screen-reader and keyboard-first
operation; contrast and focus discipline. Deferred behind core
enterprise function but tracked, not dropped.

## Phase 1 — Domain model: deployment, taxonomy, report inputs
Add `domain/deployment.py` (deployment-model descriptors, network-policy descriptors for gap 77, feature-flag definitions) and `domain/failure_modes.py` (taxonomy plus per-fault mappings as data over the catalog). Pure types. Acceptance: every catalog fault maps to at least one failure mode (test-enforced); unmapped faults fail the suite.

## Phase 2 — Engine: sandbox, demo mode, network policy
Sandbox provisioner (compose-based reference environment); demo-mode execution path with mutation backend detached and mode prominently sealed into any produced evidence ("TRAINING — no mutation performed"); network-policy enforcement (proxy/CA/allowlist) across all external calls. Acceptance: a training run produces evidence that cannot be mistaken for a production run (verifier distinguishes by mode marker).

## Phase 3 — Surface: installers, sandbox, admin
Helm deployment (self-hosted), relay/proxy configuration UX, sandbox lifecycle commands, support-bundle generation, upgrade channels. Acceptance: fresh-install walkthroughs per deployment model tested in CI cells.

## Phase 4 — Safety and evidence integration
Sandbox and demo runs pass through admission with their own ceilings (a sandbox is not a policy-free zone); support bundles reuse redaction plus 29 classification rules; compliance mappings reference sealed evidence only. Acceptance: the 20 acceptance walkthrough (deploy → authenticate → policy → approve → execute → observe → stop → recover → verify → export) runs without engineering intervention.

## Phase 5 — Tests, regression guards, negative controls
Failure-mode coverage tests, sandbox provisioning tests, demo-purity tests (mutation backend receives zero calls), network-policy tests (proxy/CA/allowlist honored; direct egress refused under policy). Negative controls: a demo-mode run presented as production evidence is rejected by the verifier; an air-gapped install attempting egress fails closed. Acceptance: full matrix green.

## Phase 6 — Docs, honesty gates, rollout
Deployment guides per model, sandbox tutorial, compliance-mapping methodology (what a pack proves vs. what the customer must still do), support process with SLA/SLO definitions (gap 110), telemetry/privacy policy. Rollout: local plus sandbox first, self-hosted second, SaaS and air-gapped last. Acceptance: the commercial readiness checklist in the original draft becomes a gated list, each item naming its proof.

## Dependencies
08 (platform), 09 (org model), 12 (evidence-backed reports), 14 (simulate path), 22 (coverage inputs), 29 (bundle redaction).

## STATUS
- Phase 1 (domain model): DONE — `domain/deployment.py` (four deployment models, gap-77 network policy as fail-closed data, sealed execution-mode markers that make a demo run structurally unpresentable as production, validated feature flags) and `domain/failure_modes.py` (18-member taxonomy plus all 145 catalog faults mapped to failure mode/mechanism/symptom/risk/recovery/verification, test-enforced) landed with unit and negative-control tests
- Phase 2 (engine): DONE — `controller/sandbox_service.py` (compose-blueprint sandbox provisioner driven by an injectable runner, failing closed with a rollback instead of returning a half-built environment; demo/training mode that runs the existing `PredictionService.simulate_plan` no-mutation path with the mode marker sealed into every piece of evidence and sandbox runs admitted against the sandbox's own plan-14 ceilings) and `infra/network_policy.py` (pure policy resolution and egress decisions plus the enforcement guard every external call passes through: proxy, custom CA, private registry/Git, enforced allowlist, and an air gap that fails closed naming the cause), with 76 unit tests including negative controls
- Phase 3 (surface): DONE — `cli/sandbox_cmd.py` (`sandbox up/down/status` over `SandboxProvisioner` with the CLI's own `SubprocessSandboxRunner` injected; relay/proxy configuration UX as `--http-proxy/--https-proxy/--ca-bundle/--allow-host/--enforce-allowlist/--air-gapped/--model` flags honored-or-fail-closed before the first command; `status` reads the blueprint, registry hosts, and the compose-provider topology without touching a runtime), `cli/support_bundle_cmd.py` (`support-bundle build` via `build_support_bundle`, writing bytes to `--out` with secrets dropped-not-redacted and the redaction manifest reporting dropped fields, redacted paths, rule version, and mode banner), `cli/upgrade_cmd.py` (`upgrade channels/check` read-only over `validate_upgrade`: downgrade, unparseable version, and air-gapped-rapid refusals exit safety-refusal with the rule named), all three groups registered in `command_registry` plus `test_command_inventory`/`test_cli_exhaustive_matrix` pins, with 19 surface tests in `tests/unit/test_enterprise_surface.py` (fakes only, no live docker). Helm reuse: `deploy/mayhem/helm/mayhem` (plan 02 Phase 3 stub) already installs the self-hosted deployment model, so no second chart was minted — the walkthrough's live `deploy` item names that chart rather than duplicating it.
- Phase 4 (safety and evidence integration): PARTIAL — `cli/enterprise_cmd.py` (`enterprise walkthrough` runs the ten acceptance steps with `SubprocessSandboxRunner` injected: sandbox/demo runs pass through admission with the sandbox's own ceilings, support bundles reuse redaction plus the mode banner, compliance mappings via `controller/compliance_map.py` cite sealed evidence digests only and refuse unsealed digests; honesty: the map is a mapping, never a certification) and the harness in `controller/enterprise_walkthrough.py` (fixed `harness_ok` to exclude live-only steps; 10 walkthrough tests in `tests/unit/test_enterprise_walkthrough.py`, fakes only). The harness proves the sequence, not the site: 4 live open items remain (live IdP for authenticate, human approver for approve, live container runtime for execute/stop/recover, live cluster for the Helm install), so the phase is PARTIAL, not DONE.
- Phase 5 (tests, regression guards, negative controls): DONE — `tests/unit/test_enterprise_phase5.py` (17 tests: all 145 catalog faults mapped asserted, sandbox provisioning through admission with ceiling-breach refusal, demo-purity as a sink measurement with moved-sink refusal, proxy/CA/allowlist/air-gap decisions through the guard with transport-never-reached, negative controls for demo-as-production rejection, demo-flag-in-production refusal, forged-marker refusal, and unsealed-digest refusal), plus the Phase 4 walkthrough tests and the failure-mode/network-policy suites they pin. Full matrix green on the related files.
- Phase 6 (docs, honesty gates, rollout): DONE — `docs/v1.1.0/20_ENTERPRISE_GUIDES.md` (deployment guides per model, sandbox tutorial, compliance methodology stating what a pack proves vs. what the customer must still do, support process with SLO definitions over the bundle manifest and an honest SLA boundary of none stated, telemetry/privacy policy of no collection, rollout local-plus-sandbox first) with the machine-checked honesty gate in `tests/unit/test_enterprise_guides.py` (8 tests: no unqualified compliance/certification claim, live proofs named as open, refusal codes quoted exist in code, rollout order; each checker proved to bite). Also fixed a latent defect found while mapping: `COMPLIANCE_TEMPLATES` evidence tuples were implicitly concatenated into one string (missing commas); split into three kinds per template.

Overall: 5 of 6 phases complete, with Phase 4 PARTIAL on its live-site clause: the harness sequence is proven, and authenticate/approve/container-runtime/Helm-install remain live open items by construction.
