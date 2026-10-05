# Mayhem

**Chaos engineering for Docker and Podman, with separately scoped Kubernetes
planning and execution seams.** The documented quickstart uses a compose
blueprint. Mayhem compiles a declarative `kind: drill` document into a frozen,
safety-gated plan, injects supported faults through a capability-aware toolkit,
and derives the run verdict from recorded observations.

Everything lands in SQLite — steps, probes, criteria evaluations, decisions —
so nothing is ever "trust me, it worked."

Kubernetes source support is layered and must not be collapsed into one
"supported" claim: manifest planning, planner support, executor support, and
live resolution are separate states. The legacy `KubernetesAdapter` remains
unavailable, and catalog-only faults are not executable merely because they are
defined. See the [Kubernetes status](#kubernetes-status) section and the
[documentation authority index](docs/README.md).

```
compose blueprint ─▶ topology graph ─▶ compile drill spec ─▶ frozen plan
                                                              │
                        verdict ◀── machine criteria ◀── inject → observe → recover
                                                              │
                                                SQLite evidence + decision trace
```

- [What mayhem cannot do](#what-mayhem-cannot-do)
- [Quickstart](#quickstart)
- [A Run in One Screen](#a-run-in-one-screen)
- [Authoring a Drill](#authoring-a-drill)
- [Configuration](#configuration)
- [CLI surface](#cli-surface)
- [Campaigns](#campaigns)
- [What's new in v0.9.0](#whats-new-in-v090)
- [Safety Model](#safety-model)
- [Exit Codes](#exit-codes)
- [Architecture](#architecture)
- [Status](#status)
- [Development](#development)

---

## What mayhem cannot do

Read this before you evaluate mayhem against a kernel-level chaos tool. The
three limits below are structural: no configuration reaches them, and none is a
roadmap item pretending to be a setting.

### There is no kernel or eBPF fault injection

Mayhem has **no eBPF injection, no kernel module, and no in-kernel fault
primitive of its own**. There is no `bcc`, no `libbpf`, and no eBPF program
type anywhere under `src/`. Mayhem loads no code into the kernel and depends on
no kernel feature that a stock install does not already provide.

The whole injection substrate is userspace plus already-compiled kernel
configuration:

| Mechanism | Used for |
|-----------|----------|
| `tc qdisc … netem` | `net.*` latency / loss / duplication / reordering, and `db.slow_query` |
| `toxiproxy` | `dependency.*` and `http.*` request and response shaping |
| container-engine cgroup knobs (`docker` / `podman update`) | `cpu.throttle`, `mem.exhaust` |
| userspace allocators, writers, and file manipulation | `cpu.saturate`, `mem.*`, `fs.*`, `fd.exhaust` |
| the Kubernetes API | every `k8s.*` fault |
| `nsenter` into an existing network namespace | node- and pod-scoped `tc` |

`tc`/netem configures a qdisc that is **already compiled into the kernel**. It
is a traffic-shaping control, not an instrumentation program. That is the
closest mayhem comes to the kernel, and it is a category away from Chaos Mesh's
eBPF layer, which attaches a program to a running process and can block one
syscall, corrupt one page, or stall one `write` while everything else in the
process keeps running.

**If your failure model lives below the syscall boundary, mayhem cannot inject
it.** A fault that must be a specific `write` returning a specific `errno`, a
specific page corrupted in a specific process, or a specific syscall blocked
while the rest of the process stays healthy, is out of scope for mayhem's
substrate — not unimplemented, *unsupported*.

Seventeen catalog entries are `catalog_only` for exactly this reason. Mayhem has
no primitive to inject them, and their refusal text is the feature: it names the
missing mechanism instead of quietly substituting a weaker fault.

| Fault | The mechanism mayhem does not have |
|-------|------------------------------------|
| `app.deadlock` | a true lock cycle cannot be imposed from outside the process |
| `app.exception` | in-process bytecode injection, `ptrace`, or `/proc/<pid>/mem` patching |
| `clock.freeze` | a `libfaketime` preload or `CLOCK_REALTIME` interception |
| `cpu.interrupt_storm` | IRQ/softirq control via `/proc/interrupts` or RPS/RFS tuning |
| `cpu.steal` | hypervisor / host-scheduler control (KVM) |
| `fs.permission_failure` | a permission-preserving executor |
| `fs.read_error` | a device-mapper error target, or a FUSE shim needing `SYS_ADMIN` and a loop device |
| `fs.read_delay` | a FUSE passthrough daemon plus a `fuse` device and mount tooling in the target |
| `fs.block_device_delay` | a device-mapper delay target over a loop device, plus a read-only snapshot to reactivate |
| `mem.fragment` | buddy-allocator, `MADV_FREE`, or hugepage control |
| `mem.oom_kill` | an irreversible kill with no supervisor, which the compensation contract forbids |
| `process.oom_kill` | likewise; `mem.exhaust` deliberately caps at 95% of the cgroup limit |
| `process.startup_delay` | an application-aware readiness hook |
| `process.syscall_error` | an eBPF kprobe loader that can make a named syscall return an `errno` |
| `process.syscall_return_mutation` | a CO-RE return-value rewrite; a kprobe loader alone does not give one |
| `dependency.malformed_response` | a protocol-aware response proxy |
| `k8s.image_pull_slow` | a registry-pacing runtime |

Every one of these is discoverable rather than hidden: `mayhem discover faults
-e FAULT_ID` prints the refusal and the suggested alternative. Note that
`k8s.*` faults have a separate, independent limitation — the Kubernetes
executor and resolver seams exist in source but no live cluster acceptance is
claimed anywhere. See [Kubernetes status](#kubernetes-status).

### No fault in this repository is `verified-live`

`verified-unit` is a claim about **mayhem's own code**, not about the fault
working. It means that fault id's parameter grammar, refusal path, and
compensation contract are deterministic and covered by recorded unit evidence.
It says nothing about whether the fault has ever perturbed a running system.
Of the **145** catalog faults, **128** are `verified-unit` and **17** are
`experimental`. **0 of 145 are `verified-live`**, and none is `stable`.
Reading `verified-unit` as "this works" is a misreading, and this README
previously invited it.

`verified-live` is earned only from a recorded live-run record: an injected
effect that moved a signal, an undo that actually ran, and a probe that
confirmed the pre-injection baseline was restored within tolerance, on the
required engines. An empty evidence store yields zero live-verified faults —
there is no "presumed live" default, no flag, and no code path that grants the
level without a record. None of them is reachable in this repository today.

The reported maturity level is **derived at read time** from the evidence
store, not stamped onto the catalog entry. Delete the evidence for a fault and
its reported level drops with it. Two consequences follow, and both are
statements about what mayhem has *not* done. The absence of
`verified-live` across the whole catalog — 0 of 145 — is a **missing**
verification program, not a **failed** one: nothing here has been shown to work
against a real system, and nothing has been shown not to. And because the
derived level is only ever a function of recorded evidence, a fault that drops
to `verified-unit` is saying that mayhem's own parameter, refusal, and
compensation code is still deterministic — **not** that the fault works. The
`experimental` and `verified-unit` populations together are a catalogue of
contracts, not a reliability claim.

### Fault packs are integrity-checked, not signed

The pack format carries a `signature: str` and a `signer: str` with **no public
key, no key id, no algorithm identifier, and no trust store**, and no
signature-verification dependency is in the build. Mayhem therefore **cannot
verify a pack signature**. What the field holds is an assertion of authorship by
whoever wrote the file — the same trust a comment carries. Every pack fault's
refusal names its signer as an unverified *claim*, and every pack verdict
reports `signature NOT VERIFIED`.

What a pack can prove is **integrity**: `declared_digest` is a SHA-256 over the
canonical pack document and the loader checks it against the bytes on disk.
That detects tampering. It says nothing about who wrote the pack, and the two
axes are never collapsed into one "verified" flag. Because authorship is an
unverified claim, do not describe a mayhem fault pack as signed, verified, or
trusted.

---

## Quickstart

**Prerequisites**

- Python 3.12+
- Docker with Compose v2, or Podman selected with `--podman`

The Kubernetes client ships as a default dependency of the distribution, so
there is no separate install extra. The Kubernetes paths still need a reachable
cluster, a valid kubeconfig context, and the capabilities a fault family
declares. The checked-in documentation does not certify any live cluster.

**Install**

```bash
pip install mayhem-cli        # one bundle; console command is `mayhem`
```

**Run the bundled example**

A complete, self-contained six-service stack lives in
[`examples/testCase/`](examples/testCase/).

```bash
cd examples/testCase
docker compose up -d                          # 0. bring the stack up
mayhem discover topology --compose docker-compose.yml   # 1. blueprint → live graph
mayhem prepare validate mayhem.yaml --compose docker-compose.yml  # 2. compile + safety gates (injects nothing)
mayhem run mayhem.yaml --compose docker-compose.yml --execute  # 3. inject → observe → recover → verdict
```

Omit `--compose` and Mayhem auto-detects `docker-compose.yml` (or
`compose.yml`) in the current directory.

`validate` and `plan` compile from the compose blueprint and do not inject a
fault. Topology construction may still inspect an available container runtime
for current-state data. `run` applies its impact gate and records the actual
execution outcome.

The bundled spec exercises the compose-supported fault families used by the
example stack. The [`examples/k8s`](examples/k8s) directory is a separate
manifest-backed planning example. Its presence does not prove live-cluster
execution, and the current catalog is larger than the original nine-fault
example. See [Targets (cross-runtime)](docs/drill-spec.md#targets-cross-runtime)
for the authored target syntax.

---

## A Run in One Screen

A clean run needs no interpretation — the verdict is one line away.

```
$ mayhem run mayhem.yaml --compose docker-compose.yml --execute

# Run r-process-drill-8f2a1c
**status**: completed
**verdict**: pass
**success criteria**: ALL PASS
- [PASS] status:api-up.status PASS (expected 200, got 200)
- [PASS] latency:api-up.latency_ms PASS (31.2 <= 500.0)
**observations**: 2/2 sources collected
**decisions**: 5 governing decision revisions (snapshot in the run row)
**wall**: 32.4s

run r-process-drill-8f2a1c — inspect with `mayhem inspect history r-process-drill-8f2a1c`
```

Reading the transcript, top to bottom:

1. **Status** — the run's machine state: `completed` (or `failed`/`aborted`
   with a non-zero exit and dirty-lease warnings).
2. **Verdict** — `pass`/`fail` derived from the success criteria you declared
   in the spec; `undecided` when a run aborts or the spec has no success block.
3. **Success criteria** — every criterion evaluated against real observations,
   one line each, so a failure tells you exactly what drifted.
4. **Observations** — how many configured evidence sources actually delivered
   data (probes, logs, metrics …).
5. **Decisions** — the governing decision revisions that shaped this run; the
   decision trace is queryable afterward via `mayhem inspect history`.
6. **Copy-paste handle** — the run id for the follow-up commands below.

From there: `mayhem inspect runs` lists recent runs, `mayhem inspect runs --run <run-id>`
shows full recorded metadata, and `mayhem inspect history <run-id>` replays the
complete event journal (every step, probe sample, and lease for that run).
Add `--debug` to `mayhem run` to stream each step live as it happens
(`[ok] injected proc.pause 10s into testcase-api`,
`[ok] recovered ... (compensation ok)`).

---

## Authoring a Drill

A drill is one `kind: drill` YAML file — the complete DSL reference lives in
[`docs/drill-spec.md`](docs/drill-spec.md). The shape:

```yaml
apiVersion: "mayhem/v1"
kind: drill
name: checkout-recovery
hypothesis: "checkout stays available while cart writes are throttled"

config:
  risk_ceiling: high
  # Declared but not enforced — no gate reads it. The real budget is
  # blast_radius.max_concurrent_faults in mayhem.yaml.
  max_faults: 1
  timeout: 30m
  recovery: true

containers:
  cart-api:
    faults:
      - fault: net.latency
        duration: 10s
        params:
          delay_ms: 300
          jitter_ms: 25

execution:
  - sequential: [cart-api]
  - check:
      - http: http://cart-api:8080/_health
        expect:
          status: 200
```

Validate with `mayhem prepare validate mayhem.yaml`; unknown parameters, out-of-range
durations, untargetable node kinds, and capability gaps are all compile-time
errors — before anything is injected.

Faults are drawn from the catalog (net.latency, proc.kill, net.packet_loss,
TLS failure, container pause, HTTP error injection, dependency and database
faults, k8s.pod_kill, k8s.node_drain, …). The full per-fault reference —
every id, its capabilities, risk level, and compensation contract — is in
[`docs/drill-spec.md`](docs/drill-spec.md#fault-catalog).

The `containers:` block above is the docker-family authoring shape. To fault a
Kubernetes workload or node — or mix runtimes in one spec — use the
cross-runtime `targets:` block instead (exactly one of `containers:` /
`targets:` defines a spec); see
[Targets (cross-runtime)](docs/drill-spec.md#targets-cross-runtime).

---

## Configuration

Runtime policies live in `mayhem.yaml` — the *configuration* file, distinct
from a `kind: drill` spec — auto-detected in the cwd or given with `--config`.
The effective view is one command away: `mayhem prepare config show` prints the
resolved configuration and provenance; `mayhem prepare config validate` refuses
unknown keys, a missing or wrong `apiVersion`, and out-of-range sections before
anything runs.

```yaml
apiVersion: mayhem/v1        # required; anything else is rejected
policy:
  allow_faults: null         # null = whole catalog; set to restrict
  deny_faults: []            # fault ids never injectable
  risk_ceiling: null         # tightened by the drill ceiling at plan time
  allow_critical: false      # config-side half of the critical opt-in
  critical_fault_acks: []    # per-fault acks; critical faults need allow_critical + ack + --allow-critical
blast_radius:
  max_services_pct: 50.0
  max_hosts: 2
  max_concurrent_faults: 3
  max_duration_per_fault_s: 300.0
  forbidden_fault_pairs: []  # pairs such as [net.packet_loss, net.bandwidth]
  damage_quota:               # cumulative damage-seconds across the whole plan
    budget_s: 14400.0
    per_fault_ceiling_s: 3600.0
    window_s: 604800.0
storage:
  path: mayhem.db
  artifacts_dir: .mayhem/artifacts
toolkit:
  binaries: {}               # pin a named tool's binary
runtime: docker              # docker | podman | kubernetes
target:
  containers: []             # explicit discovery targets without compose
kubernetes:
  context: null              # kubeconfig context
  namespace: null            # null = no namespace filter
recovery_grace: 300.0
log_level: INFO              # DEBUG | INFO | WARNING | ERROR
maniac:
  level: 2
  run_level: 10
  seed: null
```

Layering, in increasing precedence: **built-in defaults → selected YAML →
`mayhem.{profile}.yaml` → allowlisted environment variables → programmatic
CLI overrides**. Profile overlays are separate files selected with `--profile
NAME`; there is no `profiles:` key inside the base file. The environment layer
only honours `MAYHEM_STORAGE_PATH`, `MAYHEM_ARTIFACTS_DIR`, and
`MAYHEM_LOG_LEVEL`. The current CLI uses `--config` and `--profile` to select
layers; it does not expose a generic flag that maps arbitrary fields into
configuration.

Drill-level `config.risk_ceiling` composes with the policy ceiling and can
only tighten it.

The full configuration reference is in
[`docs/config.md`](docs/config.md).

---

## CLI surface

The active CLI is workflow-oriented: `discover`, `prepare`, `experiment`, `run`, `inspect`, `recover`, and `extend`. Guided `init` and `doctor` are active, and all legacy root commands and aliases have been removed. Exit codes, machine-readable fields, and database migrations remain stable.

The command inventory, global options, and stable exit codes are generated from
[`src/mayhem/cli/command_registry.py`](src/mayhem/cli/command_registry.py) and
[`src/mayhem/cli/exit_codes.py`](src/mayhem/cli/exit_codes.py).

Root options precede the command. Unique prefixes work at the root and in the workflow groups.

| Command group | Purpose |
|---------------|---------|
| `mayhem discover` | Discover topology, engines, faults, and capabilities. |
| `mayhem pack` | Validate and load a fault pack. **Integrity-checked only — the pack format declares no key, no algorithm, and no trust store, so authorship is an unverified claim and every verdict reports `signature NOT VERIFIED`.** See [Fault packs are integrity-checked, not signed](#fault-packs-are-integrity-checked-not-signed). |
| `mayhem prepare` | Validate configuration, prepare dependencies, and compile plans. |
| `mayhem experiment` | Show, validate, and explore authored experiments. |
| `mayhem run`, `mayhem maniac` | Execute authored or randomized drills. A drill's `steady_state:` block is graded against a previous run's captured baseline with `--baseline-from RUN_ID`; the report names the reference it was measured against, and a run id with nothing recorded is refused rather than silently re-baselined. |
| `mayhem inspect` | Inspect runs, history, coverage, next actions, leases, and diagnostics. |
| `mayhem recover`, `mayhem janitor` | Recover runs and clean leases. |
| `mayhem stop` | **Stop one run, or every live run in an environment.** Walks the emergency stop ladder — freeze dispatch, cancel pending, compensate active, reconcile, residue-scan, verify, seal — and prints the reason, the stages that completed, and the POSTFLIGHT verdict. A residue finding makes the run read `DIRTY`, never `CLEAN`; a stop that could not finish reads `UNKNOWN` and names the stage it stalled at, because "probably recovered" is not a state. `--environment` requires the `emergency_stop` role and is refused without it. `--preflight` runs the refusing preflight gate first and prints its checklist, with an unreachable port shown as `UNAVAILABLE`; a refusal stops nothing. `--reason` is required: a stop with no reason cannot be sealed. |
| `mayhem extend` | Inspect and extend faults, capabilities, dependencies, and providers. |
| `mayhem game-day` | Plan and run controlled game-day sessions with named approvals. |
| `mayhem bundle` | Verify a portable evidence bundle offline. |
| `mayhem policy` | Author, publish and explain policy bundles. `publish` writes an immutable, digest-pinned version; `retire` tombstones one (there is no delete, because an approval still names it); `explain PLAN` prints the verdict the engine reached under a named policy — every denial naming the rule, what it observed and what it wanted instead — exits non-zero on a DENY, and mutates nothing. |
| `mayhem completion` | Print a bash/zsh/fish completion script. |
| `mayhem campaign`, `mayhem commands`, `mayhem init`, `mayhem doctor`, `mayhem verify` | Manage campaigns, inspect the command map, onboard, diagnose, and verify evidence. |
| `mayhem certify` | Certify a fault on one live runtime cell, or ask whether it can run there — **0-of-145 faults are live-verified, because no live cell has been certified yet.** `certify run` provisions a disposable container, executes the drill through the normal run path, residue-scans the cell, and records a certification record; a refused attempt is recorded as a refusal, never as a pass. `certify matrix` answers compatibility questions without executing; `certify regress` is the CI gate that fails a build when a previously certified fault goes red, and refuses to report green when nothing was re-run. Every maturity it reports is gated by the certification record store, so nothing is presented as live-verified without a stored record behind it. |
| `mayhem advisor` | Rank reliability findings against the criteria a sealed inputs document declares, replay one incident capture into a traced candidate, and browse the scenario library. `advisor submit` takes a candidate through the shared compile-and-gate path and **executes nothing**; the service holds no store, so no database is read. |
| `mayhem boundary` | Render a recorded search as a resilience boundary report, and review a generated candidate beside the authored plan. Read-only, and the candidate payload is untrusted: it is scanned by the analytics domain's one authority check and by nothing else. |
| `mayhem risk-preview` | Show a run's target set and the risk preview of what it would do, and read the dependency view — blast radius, health, and coverage per node. **Read-only with no `--force` and no `--record`:** the store is opened, queried, and closed, and the gate probe runs against a cloned context so it appends nothing to the safety record a real run is judged by. Incident history has **no witness on this surface**, so that column renders `UNAVAILABLE` with the port named rather than a zero. |
| `mayhem api` | Inspect the control plane this build actually serves: every endpoint with the role it requires, the OpenAPI document generated from that route table, the UI pages, and a rendered page body. **There is no `serve` sub-command** — the only bytes this group writes are the `--out` path a caller names for the OpenAPI document. |
| `mayhem lowlevel` | List every declared low-level primitive with its disposition and mechanism, and explain one in full. `lowlevel admit` runs the admission gate and **never injects anything**: in this build the gate refuses every low-level request, because this build ships no eBPF loader, FUSE shim, device-mapper target, or JVM agent. That refusal is the output, and there is no `--force` and no `--apply`. |
| `mayhem probe` | Author a probe definition and the pin a plan must carry, author a stop condition against it, and print the tolerance-type reference. `probe uncover` reports which declared families this run **cannot** see, and why; the shipped connectors are read-only, so anything unbound is `UNAVAILABLE` rather than a silent zero. |
| `mayhem schedule` | Register, enable, disable, and delete recurring schedules, evaluate them at an instant, simulate the anti-starvation guarantee, and read the claim ledger of every slot a schedule attempted. **`schedule tick` evaluates and reports and dispatches nothing**, and `schedule add` writes a definition without ever firing it. |
| `mayhem game-day-step` | Bind a scheduled drill to a game-day session and gate when it runs. `inject` stages the dispatch **held**, with no flag to stage it released, because the hold is the gate the scheduler reads at fire time; `release` names the facilitator who lifted it, and `hold`, `note`, and `steps` record and report the session's evidence. |
| `mayhem ha` | Promote this controller or be refused and say why, rotate credentials under the deployment's rotation policy, verify a presented certificate against the configured authority, and verify a signed update manifest. **There is deliberately no "we cannot reach the primary, so take over" flag** — that is the branch which turns a partition into a split brain — and the update check **verifies and never installs**. |
| `mayhem ci` | Render a pinned GitHub Actions workflow or GitLab CI component, and evaluate a pull request's checks, **exiting non-zero unless they all passed**. No graph means no target check, so an unreachable control plane comes back `UNKNOWN` and still exits non-zero rather than passing a question nobody asked. `ci status` prints the commit status a verdict *would* post and says plainly that it posted nothing: this repository ships no forge client, so the status port is unbound. |

Use each command's current `--help` output for accepted arguments. `mayhem commands show`
prints the live command map, and `tests/unit/test_cli_exhaustive_matrix.py` fails
when a registered command is missing from the active surface.

---

## Campaigns

A campaign groups authored drill-spec paths and runs them sequentially.

```bash
mayhem campaign create black-friday \
  --description "BFCM chaos" --hypothesis "checkout survives every single-fault failure"
mayhem campaign add-experiment black-friday mayhem.yaml
mayhem campaign add-experiment black-friday checkout-recovery.yaml
mayhem campaign start black-friday
mayhem campaign run black-friday --compose docker-compose.yml --execute
```

The current CLI creates campaigns in `draft`, `approve` moves a draft to
`approved`, `start` begins a draft or approved campaign, `run` executes the
stored spec paths, `pause` and `resume` stop and continue a running campaign,
and `archive` or `abort` sets the corresponding terminal status. The current
command surface does not expose campaign scheduling, priority ordering, or
policy/window editing. See the
`mayhem commands show`.

---

## What's new in v0.9.0

v0.9.0 is a truth-and-evidence release. It adds no new fault-injection power; it
makes what Mayhem already does **verifiable**. Every new surface below is
plan-only until explicitly executed, and every claim is recorded in evidence.

| Area | What it gives you | Where |
|------|-------------------|-------|
| Explicit intent | Every mutating command needs an approval; `--dry-run` previews and returns before any engine exists. | `mayhem run --execute`, `src/mayhem/cli/command_registry.py` |
| Runtime context | Engine, target, and namespace resolved once and propagated; a target-type mismatch is refused **before** any lease or subprocess. | `mayhem doctor`, evidence `k8s_context` |
| Capability truth | What each fault can actually do per engine, with a reason and a source of truth for every blocked row. | `mayhem discover capabilities [--explain] [--blocked]` |
| Replay capsules | A versioned, digest-checked capsule per run; export and validate offline. | `mayhem inspect replay export\|validate RUN_ID` |
| Redaction | Redaction enforced at the write boundary, so a directly-built envelope cannot leak; counts-only metrics in evidence. | evidence `redaction_metrics` |
| SLO criteria | Provider-neutral thresholds with explicit units and windows; a missing observation **fails** rather than passes. | `slo:` in the [drill spec](docs/drill-spec.md#slo-criteria-v090) |
| Scenarios | Typed variables, time windows, and conditional steps compiled to a deterministic plan. | `mayhem experiment compose` |
| Coverage graph | Service × fault × engine coverage with blocked runs excluded, plus baseline diffs. | `mayhem inspect graph`, `mayhem inspect coverage-diff` |
| Campaign resume | Durable checkpoints; a verified experiment is never repeated without `--retry-verified`. | `mayhem campaign resume-plan` |
| Residual impact | Before/after comparison proving the system came back; an unavailable source reads `unavailable`, never `clean`. | `mayhem inspect residual` |
| Game days | Sessions with a freeze window, named approvers, and dual control for critical faults. | `mayhem game-day` |
| Provider sandbox | Default grant is read-only. Fault packs are integrity-checked against a SHA-256 digest; a pack's declared signature is an unverified claim of authorship, not authentication. | `src/mayhem/providers/` |
| Observability | Read-only Prometheus/Loki connectors (bounded timeout, response-size cap, redacted errors) plus local OpenTelemetry spans. | `src/mayhem/observability/` |
| Evidence bundles | Hash-chained, offline-verifiable bundles of a run's evidence. | `mayhem bundle verify PATH` |

Three honesty rules are worth stating plainly, because they change what output
means:

- **No backend means no effect.** `start_load`, `stop_load`, and `notify` have
  no executor yet. They report `acknowledged_no_backend` and the run is *not*
  clean — they never look like success.
- **No live verification is claimed without a live run.** The capability
  dashboard reports `live=false` for every row in this repository; `live=true`
  can only come from a recorded live run.
- **No fault is live-verified in this repository either.** 0 of 145 catalog
  faults hold `verified-live`. `verified-unit` is a statement about mayhem's own
  parameter, refusal, and compensation code — not evidence that a fault works.
  See [No fault in this repository is `verified-live`](#no-fault-in-this-repository-is-verified-live).

### Shell completion

`mayhem completion SHELL` prints a completion script to stdout. Nothing is
installed and nothing is executed — you choose where it goes. Completion is
dynamic, so the candidates always match the commands your installed version
actually has:

```bash
mayhem completion bash >> ~/.bashrc
mayhem completion zsh  > "${fpath[1]}/_mayhem"
mayhem completion fish > ~/.config/fish/completions/mayhem.fish
```

`bash` needs **bash >= 4.4**; macOS ships 3.2, where dynamic completion is not
available — use `zsh` or `fish` there, or install a newer bash. The generated
bash script says so in its header.

```bash
mayhem --version                     # installed version, or 0.0.0+source in a checkout
mayhem discover capabilities --explain k8s.pod_kill
mayhem bundle build RUN_ID --out bundle/   # assemble a portable, hash-chained bundle
mayhem bundle verify bundle/                # re-derive every hash from the bytes
```

### v0.9.0 status

The v0.9.0 planning package was scaffolding and has been removed; the behavior
it described is what is implemented and documented above. What remains verified:

| Gate | Result |
|------|--------|
| `pytest tests/unit tests/integration tests/e2e` | PASS |
| Coverage of the v0.9.0 modules | 100% on 14 of 15; `domain/scenarios.py` 99% (3 unreachable defensive lines) |
| `uv build --sdist --wheel` + `scripts/verify_release_artifacts.py` | PASS (9 checks) |
| Wheel install, import, console scripts, `mayhem --version`, `python -m mayhem` | PASS |
| GitHub Actions on `v0.9.0` | PASS — unit, integration, e2e, schema, ruff-fatal, package build, wheel smoke, artifact verification |
| Repository-wide `ruff` / `mypy` / `lint-imports` | Pre-existing failures, advisory only (not release-gating) |
| Live Kubernetes / remote-agent execution | Not claimed, and not enabled by default |

---

## Safety Model

- **Risk ceilings.** Every catalog fault carries a risk level; injection is
  refused when either the policy or the drill ceiling is exceeded.
  `critical`-risk faults (e.g. `k8s.node_drain`) need a **triple opt-in**:
  `policy.allow_critical: true`, a per-fault ack in `policy.critical_fault_acks`,
  and the `--allow-critical` CLI flag.
- **Concurrency budget.** `blast_radius.max_concurrent_faults` in the layered
  `mayhem.yaml` is the control that actually refuses a plan; it counts the
  prefix of fault *steps* seen so far and is never reset. The drill spec's
  `config.max_faults` is a declared field that **no gate reads** — it bounds
  nothing, and a wider `parallel:` step queues into rounds rather than escaping
  the budget. See [Fault budgets](docs/drill-spec.md#fault-budgets).
- **Duration caps.** Per-fault `duration` beyond the catalog maximum is a
  compile error.
- **Capability gating.** Faults declare the capabilities they need
  (docker engine, kubernetes_engine, net_admin, process control, …); the plan
  is proven against the live graph by the impact gate before run — never
  assumed.
- **Compensation contracts.** Reversible faults run their declared inverse;
  irreversible ones are followed by workload reconciliation. A failed round
  aborts-and-recovers its own faults first, then propagates.
- **Lease hygiene.** Fault rounds hold leases with a TTL; `mayhem janitor`
  sweeps orphaned leases and expires pending runs, `mayhem recover` repairs a
  run's orphans on demand.

---

## Exit Codes

The stable identifiers and numeric values are defined in
[`src/mayhem/cli/exit_codes.py`](src/mayhem/cli/exit_codes.py) and documented in
`src/mayhem/cli/exit_codes.py`. The deterministic
documentation test rejects identifiers that are not declared in source.

---

## Architecture

The pipeline is staged so everything expensive is done up front and execution
is as small as possible:

1. **Discover** — compose discovery builds a Docker/Podman graph. Kubernetes
   has separate live-discovery and offline-manifest providers; the manifest
   provider creates logical placeholders, not live pod selections.
2. **Prepare** — `mayhem prepare config` layering (defaults → selected YAML → separate
   profile overlay → allowlisted environment values → programmatic overrides),
   plus topology, drift detection, and target revalidation.
3. **Compile & plan** — the drill spec becomes a frozen `ExecutionPlan` with
   step sequences, per-fault compensations, success criteria, and observability
   sources; fault, target, capability, and duration inputs are validated
   against the current models.
4. **Execute** — supported runtimes execute inject → hold → compensate rounds
   and record evidence. Kubernetes planner/executor presence does not by itself
   establish a reachable cluster or an available capability.
5. **Recover & report** — `mayhem janitor` sweeps orphaned leases; `mayhem
   recover status|plan|execute`, `mayhem inspect runs`, and `mayhem inspect
   history` replay recorded evidence.

**Documentation**

| Document | Contents |
|----------|----------|
| [`docs/README.md`](docs/README.md) | Documentation authority, classifications, source-of-truth map, and Kubernetes status vocabulary. |
| [`docs/drill-spec.md`](docs/drill-spec.md) | Drill DSL reference. |
| [`docs/config.md`](docs/config.md) | Current layered configuration contract. |
| `src/mayhem/cli/command_registry.py` | Current commands, options, and stable exit codes. |
| [`src/mayhem/schemas/output_v1.json`](src/mayhem/schemas/output_v1.json) | The versioned machine-output envelope; there is no rendered prose reference for it in this repository. |
| [`docs/fault-catalog/`](docs/fault-catalog/README.md) | Checked Kubernetes fault catalog status snapshot and capability gates. |
| [`docs/compensation.md`](docs/compensation.md) | Compensation lifecycle and verification contracts. |

---

## Status

| Area | Status |
|------|--------|
| Compose-oriented Docker/Podman workflow | Documented user path |
| Layered configuration, drill planning, SQLite evidence, CLI exit codes | Current checked-in references |
| Kubernetes manifest topology | Supported as an offline planning input; blueprint pods are placeholders |
| Kubernetes planner | Supports normalized `targets:` scopes and frozen-plan metadata |
| Kubernetes executor/resolver seams | Present in source and unit-tested with fakes; availability is runtime/capability dependent |
| Legacy `KubernetesAdapter` | Compatibility seam only; reports unavailable |
| Live Kubernetes cluster acceptance | Not claimed by repository documentation |
| Catalog-only Kubernetes faults | `k8s.image_pull_slow`; excluded from the available-fault register and refused before mutation |
| **Kernel / eBPF / BPF fault injection** | **Not implemented and not planned for 1.0.0.** No eBPF program, no kernel module, no in-kernel primitive. See [What mayhem cannot do](#what-mayhem-cannot-do) |
| **`verified-live` faults** | **0 of 145.** The rung is derivable from recorded live-run evidence and no such evidence exists. See [No fault in this repository is `verified-live`](#no-fault-in-this-repository-is-verified-live) |
| **`verified-unit` faults** | 128 of 145 — a claim about mayhem's own parameter/refusal/compensation code, not about the fault working |
| **`catalog_only` faults** | 17, all refused before mutation. Refusal text names the missing mechanism; it is not a weaker substitute |
| **Fault-pack signatures** | **Cannot be verified.** Integrity (SHA-256) only; authorship is an unverified claim |
| v0.9.0 core truth work (intent, admission, capability truth, replay, redaction) | Implemented; unit + integration tested |
| v0.9.0 expansion work (coverage graph, SLOs, scenarios, resume, residual, game day, sandbox, connectors, bundles) | Implemented; plan-only until executed |
| Web UI / REST API | Planned |

### Kubernetes status

The [examples/k8s README](examples/k8s/README.md) and
[documentation authority index](docs/README.md#kubernetes-status-vocabulary)
explain the separate Kubernetes states. Historical discovery reports and the
discovery reports are retained in git history for traceability and must not be
treated as live-cluster evidence.

---

## Development

```bash
# Clone, then sync the dev dependency group (requires https://docs.astral.sh/uv/):
uv sync --group dev

# Run all tests
uv run pytest

# Check the release truth baseline (docs, Justfile, packaging vs. source)
uv run pytest tests/unit/test_release_contract.py

# Build the sdist and wheel
uv build

# Lint
uv run ruff check src/

# Type check (strict is configured per module)
uv run mypy
```
