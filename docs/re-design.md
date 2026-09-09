Yes. Looking at the README, DSL reference, and repository exploration together, Mayhem is already unusually mature in its **core execution/safety loop**. The biggest opportunities are not “add 50 more fault types”; they are making the product **more operable, more diagnosable, more composable, and much better from the CLI**.

The strongest current foundation is topology → frozen plan → gated injection → observation → compensation → machine verdict → SQLite evidence. 

## 1. Biggest problems I see

### A. The CLI is powerful but feels like an internal engineering CLI

There are many commands, but the UX model isn't fully coherent.

You currently have:

```text
mayhem
├── validate
├── plan
├── run
├── maniac
├── status
├── history
├── recover
├── janitor
├── dependency
├── experiment
├── topology
├── toolkit
├── config
└── campaign
```

and then some functionality exists only as internal/library machinery. 

The biggest UX problem is that users have to understand Mayhem's internal architecture to discover what to run.

For example:

```bash
mayhem topology discover
mayhem toolkit list
mayhem validate
mayhem plan
mayhem run
mayhem status
mayhem history
mayhem recover
mayhem janitor
```

That's technically clean, but the user mental model is more like:

```text
inspect → prepare → attack → watch → explain → recover → report
```

I'd redesign the CLI around that workflow.

---

# 2. CLI improvements I'd prioritize

## `mayhem doctor`

This should probably be one of the first additions.

```bash
mayhem doctor
```

Output:

```text
Mayhem Doctor

Runtime
  ✓ Docker 28.1
  ✓ Compose v2
  ✓ Python 3.12
  ✓ SQLite WAL

Toolkit
  ✓ docker
  ✓ tc
  ✓ iproute2
  ✗ k6                required by net.load
  ✓ stress-ng

Permissions
  ✓ container control
  ✓ net_admin
  ! process control unavailable

Topology
  ✓ 6 services discovered
  ✓ no topology drift

Ready
  31/38 faults executable
  7 blocked by missing capabilities
```

Right now `toolkit list` and dependency checking expose pieces of this, but they are fragmented. The existing `--host` behavior is also misleading because the host is just a label and probing still occurs locally.  

`doctor` should become the canonical environment diagnostic.

---

## `mayhem inspect`

Instead of making users know topology-specific commands:

```bash
mayhem inspect
mayhem inspect topology
mayhem inspect faults
mayhem inspect capabilities
mayhem inspect config
mayhem inspect runs
```

Or even:

```bash
mayhem show topology
mayhem show faults
mayhem show config
mayhem show run <id>
```

`experiment show`, `config show`, `toolkit faults`, `topology discover`, etc. currently make the CLI feel fragmented.

---

## `mayhem explain`

This would be extremely valuable.

```bash
mayhem explain net.packet_loss
mayhem explain run r-checkout-123
mayhem explain failure r-checkout-123
```

For a fault:

```text
net.packet_loss

Risk:          medium
Maximum:       300s
Requires:      net_admin
Targets:       container, service

Injection
  tc netem loss

Compensation
  tc rule removal

Verification
  interface restored
  route restored

Blocked because:
  testcase-api lacks NET_ADMIN
```

For a failed run:

```text
Why did this run fail?

1. net.latency injected successfully
2. api-health remained healthy
3. db-connection check failed
4. recovery succeeded
5. final criterion:
   db-health.status == 200
   observed: 503

Likely failure:
  downstream DB dependency unavailable
```

You already have enough evidence and decision information to build this. The current architecture explicitly records events, observations, criteria, decisions, leases, etc. 

---

# 3. CLI output needs a much better hierarchy

Current output is mostly text/markdown/JSON. There is no HTML/export/dashboard layer. 

I'd standardize every command around:

```text
summary
details
machine output
```

For example:

```bash
mayhem run drill.yaml
```

should give the human-readable summary.

```bash
mayhem run drill.yaml --json
```

should give a stable machine schema.

```bash
mayhem run drill.yaml --quiet
```

should emit only the final result.

And:

```bash
mayhem run drill.yaml --watch
```

should provide a rich live execution display.

Right now JSON isn't consistently available across the whole CLI. The README lists JSON support for some commands, but not as a universal CLI contract. 

I'd make `--json` a **global output mode**.

Also add:

```bash
--format text|json|yaml|table
--no-color
--quiet
--verbose
```

---

# 4. Make `run` the center of the CLI

I'd make the lifecycle much more discoverable:

```text
mayhem init
mayhem doctor
mayhem discover
mayhem plan
mayhem run
mayhem watch
mayhem report
mayhem recover
```

Then advanced namespaces can remain:

```text
mayhem topology ...
mayhem toolkit ...
mayhem campaign ...
mayhem config ...
```

The current command layout exposes implementation concepts instead of user workflows.

---

# 5. Add `mayhem init`

This is a huge missing UX feature.

```bash
mayhem init
```

Interactive or non-interactive:

```text
Detected:
  docker-compose.yml
  6 services

Create:
  mayhem.yaml

Suggested checks:
  ✓ HTTP health endpoint
  ✓ postgres connection
  ✓ service dependencies

Suggested first faults:
  1. proc.pause
  2. container.restart
  3. net.latency
  4. mem.exhaust
```

Could support:

```bash
mayhem init --from-compose
mayhem init --template web-service
mayhem init --minimal
```

This turns Mayhem from something you configure manually into something you can start using in minutes.

---

# 6. `validate` needs to become much more useful

Currently:

```bash
mayhem validate
```

is essentially “compile and run safety gates without injecting.” 

I'd make it report a complete readiness matrix:

```text
Validation

Spec             ✓
Topology         ✓
Targets          ✓
Risk policy      ✓
Concurrency      ✓
Duration         ✓
Capabilities    35/38
Impact            31/38
Compensation     38/38

Executable faults
  ✓ 31
  ⚠ 4 missing host capability
  ✗ 3 impossible target

Overall: READY WITH WARNINGS
```

And:

```bash
mayhem validate --explain
mayhem validate --strict
```

`--strict` could make warnings fatal.

---

# 7. The fault catalog needs better structure

The 54-fault catalog is good, but it's currently primarily a flat catalog. 

Add metadata such as:

```yaml
fault: net.packet_loss

category: network
risk: medium

tags:
  - connectivity
  - degradation
  - transient

failure_modes:
  - packet_loss
  - retransmission
  - latency_increase

affects:
  - availability
  - latency
  - throughput

requires:
  - net_admin

compensation:
  type: inverse

verification:
  - interface_clean
  - rule_removed
```

Then CLI:

```bash
mayhem faults search network
mayhem faults search --tag database
mayhem faults search --risk high
mayhem faults search --requires net_admin
mayhem faults recommend checkout
```

This is much more powerful for future automatic experiment generation.

---

# 8. Add experiment templates

Right now users construct everything manually.

Add:

```bash
mayhem template list
mayhem template show api-resilience
mayhem template apply api-resilience
```

Examples:

```text
api-resilience
database-resilience
worker-resilience
network-resilience
resource-exhaustion
kafka-consumer
redis-dependent-service
```

Then:

```bash
mayhem init --template api-resilience
```

generates a drill.

---

# 9. The M5 subsystem is probably your highest-value unfinished feature

This is the biggest architectural opportunity in the repository.

The repo already has:

* candidate generation
* candidate safety gates
* feasibility gates
* resource-conflict gates
* coverage tracking
* maniac selection
* campaign engine
* reports

but it's essentially orphaned from the CLI. 

That's an unusually valuable unfinished subsystem.

I'd expose it directly.

For example:

```bash
mayhem explore
mayhem explore --budget 30m
mayhem explore --coverage
mayhem explore --seed 42
```

Conceptually:

```text
discover topology
      ↓
generate candidate faults
      ↓
safety gate
      ↓
feasibility gate
      ↓
resource conflict gate
      ↓
select highest-value experiment
      ↓
run
      ↓
update coverage
      ↓
repeat
```

Then Mayhem goes from:

> “Here is a fault engine.”

to:

> “Find the most valuable resilience experiments for me.”

That is a much stronger product.

---

# 10. Add a real coverage model

Your existing M5 machinery already points toward this, and the report describes the ASCII heatmap and ranked backlog. 

But I'd turn coverage into a first-class concept.

```bash
mayhem coverage
mayhem coverage --service checkout
mayhem coverage --fault network
mayhem coverage --json
```

Example:

```text
Checkout

Availability       ████████░░ 80%
Latency            ██████░░░░ 60%
Database           █████░░░░░ 50%
Network             ███████░░░ 70%
Resource pressure   ██░░░░░░░░ 20%

Untested:
  net.connection_reset
  db.connection_exhaust
  mem.exhaust
```

And:

```bash
mayhem next
```

should answer:

> “What should I test next?”

That could be one of Mayhem's killer features.

---

# 11. Add a hypothesis lifecycle

You already have:

```yaml
hypothesis:
```

and the README frames drills around proving resilience. 

Make the hypothesis a first-class result:

```text
Hypothesis

"checkout stays available while cart writes are throttled"

Expected:
  checkout availability >= 99%
  latency < 800ms

Observed:
  availability: 97.2%
  latency: 1240ms

Result:
  FAILED

Evidence:
  cart-api → database
  DB pool exhausted
```

That makes Mayhem feel like an experimental system rather than a fault injector.

---

# 12. Add baseline comparison

This is one of the most important features I'd add.

Today you can run a drill and evaluate criteria.

But users really want:

> Did resilience improve or degrade?

Add:

```bash
mayhem baseline create
mayhem baseline show
mayhem run drill.yaml --compare baseline
```

Result:

```text
Baseline vs current

Availability
  baseline   99.98%
  current    99.72%
  delta      -0.26%

p95 latency
  baseline   210ms
  current    390ms
  delta      +180ms

Recovery
  baseline   8.2s
  current    12.7s
  delta      +4.5s
```

This would be much more valuable than a static 0–100 resilience score.

---

# 13. The resilience score needs work

You currently have:

```text
step performance   35%
self-healing       35%
redundancy         30%
```

with an A–F result. 

I would **not** make this the main health metric.

The danger is that:

```text
87/100
```

looks scientific even when the weighting is arbitrary.

Instead:

```text
PASS/FAIL
+
measured metrics
+
recovery time
+
blast radius
+
coverage
+
trend
```

Then optionally:

```text
Resilience score: 87
```

as a secondary aggregate.

Better still, make score weights configurable:

```yaml
score:
  availability: 0.30
  recovery_time: 0.25
  error_rate: 0.20
  latency: 0.15
  blast_radius: 0.10
```

---

# 14. Add failure injection sequences

The DSL currently has parallel/sequential/wait/check steps. 

I'd add richer temporal behavior:

```yaml
execution:
  - inject:
      fault: net.latency
      duration: 20s

  - ramp:
      fault: net.packet_loss
      from: 1%
      to: 30%
      duration: 30s

  - repeat:
      count: 5
      steps:
        - inject: ...
        - check: ...
```

This enables realistic progressive failures.

Especially valuable:

```text
ramp
pulse
flap
soak
repeat
randomize
```

These model production incidents much better than fixed-duration individual faults.

---

# 15. Add fault dependencies / scenarios

Instead of only:

```yaml
fault: net.latency
```

support:

```yaml
scenario: database-failure
```

or:

```yaml
scenario:
  - db.connection_exhaust
  - net.latency
  - dependency.timeout
```

But importantly, use explicit policy:

```yaml
max_concurrent_faults: 2
allowed_combinations:
  - [net.latency, db.connection_exhaust]
```

You already have forbidden fault pairs, so this is a natural extension.

---

# 16. Stateful fault campaigns

Another major improvement:

```text
fault → observe → adapt → next fault
```

rather than:

```text
fault → recover → next fault
```

For example:

```yaml
strategy:
  if:
    criterion: api.latency > 1000
  then:
    inject: db.connection_exhaust
```

That turns Mayhem into adaptive chaos testing.

---

# 17. Add event streaming

You already journal events in SQLite. 

Expose them:

```bash
mayhem watch RUN_ID
```

and:

```bash
mayhem events RUN_ID
```

Possibly:

```bash
mayhem run ... --watch
```

with:

```text
00:00 topology locked
00:01 impact gate passed
00:02 fault acquired
00:02 net.latency injected
00:07 health degradation detected
00:12 recovery started
00:14 recovery verified
00:14 criterion PASS
```

This is much nicer than only getting the final summary.

---

# 18. Add artifact collection

You have an artifacts directory in configuration, but observability is mostly probes/logs/metrics/inspection. 

Add:

```yaml
artifacts:
  - logs
  - inspect
  - ps
  - network
  - processes
  - filesystem
```

and:

```bash
mayhem artifact list RUN_ID
mayhem artifact cat RUN_ID network
```

For a failed experiment, automatically capture:

```text
docker inspect
container stats
process list
network routes
interfaces
iptables/tc state
recent logs
probe history
```

This would dramatically improve debugging.

---

# 19. Add a proper report/export system

Current reporting is terminal-only and there is no HTML/export/dashboard implementation. 

I'd build:

```bash
mayhem report RUN_ID
mayhem report RUN_ID --format html
mayhem report RUN_ID --format json
mayhem report RUN_ID --format markdown
mayhem report RUN_ID --format junit
```

Especially:

### JUnit

Very useful for CI:

```xml
<testsuite name="checkout-resilience">
```

### SARIF

Useful if Mayhem eventually reports resilience/security-style findings.

### HTML

Self-contained:

```text
Overview
Topology
Fault timeline
Health graphs
Criteria
Recovery
Evidence
Decision trace
```

---

# 20. Add CI-native commands

Instead of forcing CI users to understand exit codes:

```bash
mayhem ci run mayhem.yaml
```

Output:

```text
Mayhem CI

Run: r-checkout-a81bc2f1
Verdict: FAIL
Recovery: PASS
Dirty leases: 0
Coverage delta: +12%

Exit: 6
```

And:

```bash
mayhem gate
```

could act as a policy gate:

```yaml
ci:
  require_verdict: pass
  max_dirty_leases: 0
  min_coverage: 80
  max_recovery_seconds: 30
```

---

# 21. Add Git-aware experiment tracking

This would make Mayhem much more useful in development.

Record:

```text
git commit
branch
dirty tree
repository
author
CI job
environment
compose hash
Mayhem version
```

Then:

```bash
mayhem history --since abc123
mayhem compare RUN1 RUN2
```

You already fingerprint the execution environment, which is a good foundation. 

---

# 22. Add run comparison

Another very high-value CLI:

```bash
mayhem compare RUN_A RUN_B
```

Example:

```text
                 baseline      current      delta
----------------------------------------------------
p95 latency       210ms         390ms       +180ms
error rate        0.1%          3.2%        +3.1%
recovery          5.1s          8.4s        +3.3s
criteria          8/8           6/8         -2
dirty leases      0             0           0
```

This becomes enormously useful after infrastructure changes.

---

# 23. The DSL needs some normalization

The DSL is good, but there are a few rough edges.

For example, there are two ways to describe checks:

```yaml
- check:
```

and:

```yaml
- check_spec:
```

with the documentation itself calling `check` the legacy shorthand and recommending `check_spec`. 

I'd eventually make:

```text
check
```

the only public syntax and support the old syntax only for compatibility.

Likewise, the distinction between configuration and drill specification is a little confusing because both revolve around `mayhem.yaml`.

The README explicitly has:

> drill spec

and:

> configuration file

as separate concepts. 

I'd consider renaming them:

```text
mayhem.config.yaml
drill.yaml
```

or:

```text
mayhem.yaml
drill.yaml
```

with the latter being the cleanest.

---

# 24. Some current implementation inconsistencies should be fixed

These are not future features; they're technical debt.

### Stale CLI/documentation

The repo exploration found:

* nonexistent `mayhem audit`
* missing `docs/reference/cli.md`
* stale Justfile syntax
* `mayhem recover` examples without required run ID
* obsolete `janitor sweep`
* obsolete `--process`
* old campaign `--name` syntax. 

This is exactly the kind of thing that makes a CLI feel unreliable.

I'd add a CI check that executes every documented command.

---

### Ruff should eventually become a hard gate

The release workflow deliberately doesn't gate on Ruff because of 30–49 existing violations. 

That's technical debt worth eliminating rather than accepting indefinitely.

---

### Migration/schema inconsistency

`tracked_resources` and `mutation_journal` use ad-hoc table creation instead of the migration system. 

That undermines the otherwise strong “frozen schema” story.

Move them into migrations.

---

### `--host` is misleading

This:

```bash
mayhem toolkit list --host foo
```

sounds like remote capability probing but currently probes locally. 

Either implement remote probing or remove the argument.

I'd implement it because remote agents already exist conceptually.

---

# 25. Remote execution should become real

You already have:

```text
LocalStdioTransport
SSHTransport
mayhem-agent
```

and watchdog/lease semantics. 

But the normal execution path currently runs executors in-process; the agent/transport path is largely exercised by integration tests rather than being the main execution architecture. 

That's a big missed opportunity.

I'd eventually support:

```bash
mayhem agent install HOST
mayhem agent status HOST
mayhem run drill.yaml --host worker-01
```

and a topology like:

```text
controller
    │
 ┌──┴──────┐
host-01   host-02
  │          │
agent      agent
  │          │
containers containers
```

That is necessary for serious multi-host chaos testing.

---

# 26. Kubernetes should come after the operational layer

Kubernetes is clearly the planned next milestone, but I wouldn't make it priority #1.

The current repository already has the catalog, topology node kinds, example specs, and refusal gate, but execution is still interface-only. 

I'd prioritize:

```text
M5 intelligence
↓
reporting
↓
CLI UX
↓
remote execution
↓
baseline/comparison
↓
Kubernetes
```

Then Kubernetes becomes another runtime adapter instead of consuming all development bandwidth.

---

# 27. Fault catalog: add these next

I wouldn't blindly add dozens.

I'd prioritize realistic production failures that aren't well covered:

```text
disk latency
disk error / EIO
filesystem corruption simulation
DNS response corruption
DNS NXDOMAIN / SERVFAIL variants
TLS handshake latency
certificate chain failure
CPU throttling oscillation
memory pressure oscillation
process file-descriptor leak
thread exhaustion
connection-pool exhaustion
ephemeral-port exhaustion
packet corruption
MTU mismatch
ARP failure
route disappearance
clock drift/jump
service dependency brownout
queue backlog
message duplication
message reordering
consumer pause
consumer lag
```

You already have many broad classes, so the next step should be **depth and realism**, not simply increasing the catalog count. 

---

# 28. One major feature I'd especially add: `mayhem scenario`

This could tie many of the improvements together.

```yaml
apiVersion: mayhem/v1
kind: scenario

name: checkout-db-degradation

hypothesis: >
  Checkout remains available during progressive database degradation.

stages:

  - name: baseline
    observe: 30s

  - name: latency
    fault:
      fault: db.slow_query
      duration: 30s
      params:
        seconds: 2

  - name: exhaustion
    fault:
      fault: db.connection_exhaust
      duration: 20s
      params:
        connections: 50
        host: postgres

  - name: recovery
    recover: true
    observe: 60s

success:
  ...
```

Then:

```bash
mayhem scenario run checkout-db-degradation.yaml
```

This is much closer to how real incidents happen: **progression over time**, not independent random faults.

---

# 29. My priority ranking

I'd divide everything into four tiers.

### Tier 0 — Fix the rough edges

Do these first:

```text
1. Documentation/Justfile drift
2. Remove dead CLI references
3. Migration cleanup
4. Fix/replace fake --host
5. Make Ruff gated
6. Standardize CLI output/errors
7. Universal --json
```

### Tier 1 — Best immediate product improvements

```text
1. mayhem doctor
2. mayhem init
3. mayhem explain
4. mayhem watch
5. mayhem report
6. mayhem compare
7. mayhem coverage
8. baseline support
9. artifact collection
```

### Tier 2 — Turn Mayhem into an intelligent chaos platform

```text
1. Wire M5 into CLI
2. mayhem explore
3. candidate ranking
4. coverage-driven experiment selection
5. adaptive experiments
6. scenario DSL
7. fault combinations
8. progressive/ramped faults
```

### Tier 3 — Scale the platform

```text
1. remote agents
2. multi-host experiments
3. Kubernetes runtime
4. REST API
5. web UI
6. distributed result storage
```

---

# 30. The CLI I'd aim for

Ultimately I'd want a user to learn only this:

```bash
mayhem init
mayhem doctor
mayhem discover
mayhem plan
mayhem run
mayhem watch
mayhem explain
mayhem report
mayhem compare
mayhem coverage
mayhem explore
mayhem recover
```

Then advanced internals remain available:

```bash
mayhem topology ...
mayhem toolkit ...
mayhem campaign ...
mayhem config ...
mayhem agent ...
```

That gives Mayhem a very clear product story:

```text
                    MAYHEM

          ┌──────── discover ────────┐
          │                          │
          ▼                          │
       topology                      │
          │                          │
          ▼                          │
      plan + gate                    │
          │                          │
          ▼                          │
        inject                       │
          │                          │
          ▼                          │
        observe                      │
          │                          │
          ▼                          │
       recover                       │
          │                          │
          ▼                          │
       evaluate                      │
          │                          │
          ├──── evidence ────────────┤
          │                          │
          ▼                          │
      explain/report                 │
          │                          │
          ▼                          │
       coverage                      │
          │                          │
          ▼                          │
     choose next test ───────────────┘
```

**That last loop is the piece I'd pursue hardest.** The current system already has enough of the machinery for it; the M5 subsystem is sitting there essentially waiting to become the product's intelligence layer. 

And that would differentiate Mayhem much more strongly than simply adding another 20 chaos faults: **Mayhem discovers what to test, safely chooses the next experiment, proves what happened, explains the failure, measures coverage, and chooses the next experiment.**
