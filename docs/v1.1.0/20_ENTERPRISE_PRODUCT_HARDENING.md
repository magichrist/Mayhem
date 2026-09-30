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

## STATUS — planning only, 0%
