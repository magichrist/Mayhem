# v0.9.0 Feature Brainstorm

## Prioritization model

Each opportunity is scored from 1 to 5 for operator value, trust/safety impact, differentiation, and implementation risk. The recommended v0.9.0 theme is deliberately product quality over raw catalog growth.

## P0: make Mayhem trustworthy

### 1. Capability Truth Dashboard

A command and report such as `mayhem discover capabilities --explain` would show each fault and engine through the full lifecycle:

- registered
- implementation present
- runtime binary available
- target type supported
- unit verified
- conformance verified
- live verified
- policy blocked
- compensation complete

Output includes the reason a fault is not available, not just `false`.

### 2. Execution Intent Contract

Every mutating command receives a shared approval object containing plan hash, resolved engine, target identity, policy identity, blast radius, expiry, approver, and break-glass metadata. Preview and execution become the same workflow with different intents.

### 3. Replay Capsule

Persist the exact drill spec, plan, policy, target profile, topology fingerprint, engine/tool versions, random seed, provider versions, and redacted tool argv. A later operator can verify or dry-run the capsule without reconstructing hidden state.

### 4. Proof of Recovery

Every run reports four independent states:

- mutation observed
- compensation attempted
- compensation verified
- residual impact absent or explicitly accepted

A successful compensation command without verification is never a clean success.

### 5. Plan Diff and Approval Token

Show semantic differences between the last plan and the current environment, including target changes, policy changes, engine changes, capability loss, blast-radius growth, and evidence changes. Approval tokens expire and are bound to a plan hash.

### 6. Honest Action Outcomes

`start_load`, `stop_load`, `notify`, and remote actions either receive a real backend or a distinct `acknowledged_no_backend` state. They never return an unqualified success.

### 7. Universal Redaction Boundary

One typed redaction policy runs before data reaches SQLite, stdout/stderr persistence, evidence files, reports, or debug output. It covers credentials, kubeconfig references, registry tokens, URLs with embedded credentials, environment values, and command-line secrets.

## P1: make Mayhem operationally excellent

### 8. Resilience Coverage Graph

Represent coverage as a graph of service, failure domain, fault family, target type, engine, maturity, and evidence status. Operators can answer “what failure modes are still unproven?” instead of reading catalog tables.

### 9. SLO-aware Success Criteria

Allow checks such as:

- p95 latency remains below a threshold
- error budget burn does not exceed a limit
- recovery time is below RTO
- saturation remains below a defined level
- residual dependency errors return to baseline

Mayhem can accept metrics through a provider contract while remaining usable with simple process and HTTP checks.

### 10. Game-day Mode

A guided operator session with:

- named target and environment
- maintenance window
- dual-control approvals
- freeze windows
- live campaign status
- operator acknowledgement prompts
- automatic pause on unexpected blast-radius growth
- final evidence bundle and follow-up actions

Game-day mode coordinates humans; it does not bypass policy.

### 11. Campaign Checkpoints and Safe Resume

Persist per-experiment state, lease state, retry count, last successful verification, and resume eligibility. After controller loss, a campaign can resume only the safe next step.

### 12. Fault Recommendation Engine

Recommend faults from a goal, target criticality, maturity, blast radius, expected evidence, and available capabilities. Recommendations are explanations, not hidden automation.

### 13. Resilience Budget

Define a weekly or campaign-level budget for accepted blast radius, concurrent faults, recovery time, and evidence completeness. The budget is policy, not a metric dashboard.

### 14. Scenario Variables and Branches

Add typed variables, time windows, environment overlays, and conditional next steps. A scenario can express “during business hours, degrade the read path for five minutes, then run a checkout probe,” while preserving a static compiled plan for approval.

### 15. Before/After Residual Impact

Automatically compare topology, health, resource state, logs, and selected metrics before and after compensation. The report distinguishes expected temporary impact from unexpected residual impact.

## P2: make Mayhem an ecosystem platform

### 16. Provider Sandbox

Require explicit provider permissions for filesystem, network, subprocess, environment, catalog, and target mutation. Enforce the sandbox before loading untrusted extensions.

### 17. OpenTelemetry Span for Every Mutation

Emit spans for plan, approval, lease acquisition, tool call, verification, compensation, and evidence persistence. Keep sensitive attributes out of spans by default.

### 18. Prometheus and Loki Connectors

Read-only metric and log connectors feed SLO checks and residual-impact verification. They do not grant mutation permissions.

### 19. Remote Agent Mesh

Add authenticated mTLS agents, lease ownership, reconnect semantics, authorization scopes, and offline command buffering. Keep this behind a separate conformance profile.

### 20. Signed Evidence Bundle

Create a portable bundle containing the replay capsule, policy decision, plan, lease timeline, verification results, compensation results, redacted artifacts, and a hash chain. A verifier can detect modification without trusting Mayhem’s database.

### 21. Scenario Composer CLI

Add an interactive local composer that generates a drill skeleton from a topology and goal, then emits YAML for review. It must never execute directly.

### 22. Fault Pack Marketplace Format

Define a signed, versioned package format for fault packs, provider metadata, capability declarations, test vectors, and maturity claims. Loading remains opt-in and permission-scoped.

### 23. Autonomous Recovery Verification Agent

An optional agent observes a recovering system and runs read-only verification probes. It can recommend pause/abort but cannot inject a new fault without a new approval.

### 24. Time-travel Replay

Compare two runs with normalized timelines, engine/tool version differences, topology drift, and evidence completeness. This is more useful than a raw diff of JSON logs.

### 25. Resilience Badges

Generate a signed, machine-readable badge for projects that pass a defined Mayhem resilience profile. A badge communicates a tested profile, not universal production readiness.

## Selected v0.9.0 portfolio

### Release commitment

- Capability Truth Dashboard
- Execution Intent Contract
- Replay Capsule
- Proof of Recovery
- Plan Diff and Approval Token
- Honest Action Outcomes
- Universal Redaction Boundary
- PR quality gates and package verification
- Deterministic topology/runtime test contract
- Repair of stale docs, Justfile recipes, version metadata, and release workflow

### Next release candidates

- Resilience Coverage Graph
- SLO-aware Success Criteria
- Game-day Mode
- Campaign Checkpoints and Safe Resume
- Fault Recommendation Engine
- Before/After Residual Impact
