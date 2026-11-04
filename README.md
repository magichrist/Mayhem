# ✦ Mayhem

*A warm, expressive chaos engineering toolkit for Docker and Podman — with separately scoped Kubernetes planning seams.*

Mayhem compiles a declarative `kind: drill` YAML into a frozen, safety-gated plan, injects supported faults through a capability-aware toolkit, and derives a run verdict from recorded observations. Everything lands in SQLite — steps, probes, criteria evaluations, decisions — so nothing is ever "trust me, it worked."

## ✧ At a glance

| | |
|---|---|
| **What it injects** | Process, CPU, memory, storage, network, container, node, HTTP, database, DNS, TLS, FD, dependency, and Kubernetes fault families — 145 catalog entries in total |
| **How it injects** | Userspace only: `tc`/netem, toxiproxy, container-engine cgroup knobs, userspace allocation and file writes, and the Kubernetes API |
| **How it recovers** | Reversible faults run their declared inverse; irreversible faults are followed by workload reconciliation |
| **Where evidence lives** | SQLite — every step, probe sample, criteria evaluation, and decision is recorded per run |
| **Shortest path** | `mayhem discover topology --compose docker-compose.yml` → `mayhem prepare validate` → `mayhem run --execute` |
| **Console commands** | `mayhem`, `mayhem-agent`, `kubectl-mayhem` |
| **Python** | 3.12+ |
| **License** | Proprietary |

## ♡ Get started

### Prerequisites

- Python 3.12+
- Docker with Compose v2, or Podman selected with `--podman`

The Kubernetes client ships as a default dependency, but live cluster acceptance is not claimed anywhere in this repository — manifest planning is supported as an offline input.

### Install

```bash
pip install mayhem-cli        # console command is `mayhem`
# or from source
uv sync --group dev
```

### Run the bundled example

A complete six-service stack lives in `examples/testCase/`:

```bash
cd examples/testCase
docker compose up -d                          # 1. bring the stack up
mayhem discover topology --compose docker-compose.yml   # 2. blueprint → live graph
mayhem prepare validate mayhem.yaml --compose docker-compose.yml   # 3. compile + safety gates (injects nothing)
mayhem run mayhem.yaml --compose docker-compose.yml --execute  # 4. inject → observe → recover → verdict
```

Omit `--compose` and Mayhem auto-detects `docker-compose.yml` (or `compose.yml`) in the current directory.

`validate` and `plan` compile from the compose blueprint and do not inject a fault. `run` applies its impact gate and records the actual execution outcome — and `run` requires the explicit `--execute` approval; without it, Mayhem stops at a preview and no lease is ever created.

## ✦ Features

**Drill DSL** — one `kind: drill` YAML file declares containers (per-service faults), targets (cross-runtime scopes: docker / Kubernetes workloads / pods / nodes), execution ordering (`parallel`, `sequential`, `wait`, `check`), success criteria, and observability sources. Exactly one of `containers:` / `targets:` defines a spec.

**Fault catalog** — 145 entries across process, CPU, memory, storage, network, container, node, HTTP, database, DNS, TLS, FD, dependency, and Kubernetes families. Each entry declares its risk level, required capabilities, applicable node kinds, max duration, parameter schema, and compensation contract.

**Capability gating** — faults declare the capabilities they need (docker engine, kubernetes engine, net admin, process control, fs control, sys admin), and the plan is proven against the live graph by the impact gate before anything runs — never assumed.

**Blast radius controls** — `blast_radius.max_concurrent_faults` in `mayhem.yaml` is the control that actually refuses a plan; it counts fault steps seen so far and is never reset. Per-fault duration caps and a cumulative damage quota (budget / per-fault ceiling / window) bound the blast radius further.

**Critical opt-in** — `critical`-risk faults (e.g. `k8s.node_drain`) need a triple opt-in: `policy.allow_critical: true`, a per-fault ack in `policy.critical_fault_acks`, and the `--allow-critical` CLI flag.

**Lease hygiene** — fault rounds hold leases with a TTL; `mayhem janitor` sweeps orphaned leases and `mayhem recover` repairs a run's orphans on demand.

**Campaigns** — group drill-spec paths and run them sequentially with a single policy and window. Draft → approve → start → run → pause/resume → archive/abort, with durable checkpoints so a verified experiment is never repeated without `--retry-verified`.

**Evidence bundles** — hash-chained, offline-verifiable bundles of a run's evidence, signable under a named trust root with a local HMAC-SHA256 key. `bundle verify` re-derives every hash from the bytes on disk and touches no database.

**Replay capsules** — versioned, digest-checked capsules per run; export and validate offline with `mayhem inspect replay export|validate RUN_ID`.

**Safety proofs** — `mayhem prove` renders a recorded plan's safety proof, one line per obligation, each citing the gate output and digest behind it. `--check PROOF_JSON` recompiles against the plan recorded now: a plan that moved renders the submitted proof VOID with the diff that voided it.

## ⟡ How it works

The pipeline is staged so everything expensive is done up front and execution stays small:

1. **Discover** — compose discovery builds a Docker/Podman topology graph. Kubernetes has separate live-discovery and offline-manifest providers; manifest pods are placeholders, not live pod selections.
2. **Prepare** — layered configuration (defaults → selected YAML → profile overlay → allowlisted environment values → programmatic overrides), plus topology drift detection and target revalidation.
3. **Compile & plan** — the drill spec becomes a frozen `ExecutionPlan` with step sequences, per-fault compensations, success criteria, and observability sources. Fault, target, capability, and duration inputs are validated against the current models before anything runs.
4. **Execute** — supported runtimes execute inject → hold → compensate rounds and record evidence. Kubernetes planner/executor presence does not by itself establish a reachable cluster or an available capability.
5. **Recover & report** — `mayhem janitor` sweeps orphaned leases; `mayhem recover` repairs run orphans; `mayhem inspect` replays recorded evidence.

CLI command groups: `discover`, `pack`, `prepare`, `experiment`, `run` / `maniac`, `inspect`, `recover` / `janitor`, `stop`, `extend`, `game-day`, `bundle`, `policy`, `secrets`, `certify`, `advisor`, `boundary`, `risk-preview`, `prove`, `api`, `lowlevel`, `probe`, `schedule`, `game-day-step`, `ha`, `agent`, `ci`, `cloud`, `marketplace`, `sandbox`, `support-bundle`, `upgrade`, `enterprise`, plus `campaign`, `commands`, `init`, `doctor`, `verify`, `completion`.

## ☾ Configuration

Runtime policies live in `mayhem.yaml` — the configuration file, distinct from a `kind: drill` spec — auto-detected in the cwd or given with `--config`. Layering, in increasing precedence: built-in defaults → selected YAML → `mayhem.{profile}.yaml` → allowlisted environment variables → programmatic CLI overrides.

Key sections:

- `policy` — `allow_faults`, `deny_faults`, `risk_ceiling`, `allow_critical`, `critical_fault_acks`
- `blast_radius` — `max_services_pct`, `max_hosts`, `max_concurrent_faults`, `max_duration_per_fault_s`, `forbidden_fault_pairs`, `damage_quota`
- `storage` — `path` (default `mayhem.db`), `artifacts_dir` (default `.mayhem/artifacts`)
- `toolkit` — `binaries` (pin a named tool's binary)
- `runtime` — `docker` | `podman` | `kubernetes`
- `target` — `containers` (explicit discovery targets without compose)
- `kubernetes` — `context`, `namespace`
- `recovery_grace`, `log_level`, `maniac` (level, run_level, seed for randomized rounds)

`mayhem prepare config show` prints the resolved configuration and provenance; `mayhem prepare config validate` refuses unknown keys, a missing or wrong `apiVersion`, and out-of-range sections before anything runs.

## ◈ Architecture

```
compose blueprint ─▶ topology graph ─▶ compile drill spec ─▶ frozen plan
                                                          │
                        verdict ◀── machine criteria ◀── inject → observe → recover
                                                          │
                                              SQLite evidence + decision trace
```

Layer ownership:

- **domain/** — fault definitions, capabilities, risk ladder, maturity levels, execution intent, admission, policy, compensation, safety proof, replay, evidence — zero IO, no upward imports
- **toolkit/** — tool manifests, fingerprinting, registry, tool runner
- **agents/** — executors (the only code allowed to perturb the system), impact, leases, probes, Kubernetes control/resolve/session
- **infra/** — SQLite store, evidence, budget enforcement, promotion, migrations, retention
- **controller/** — planner, safety gate, preflight gate, check gate, executor runner, recovery, stop engine, certification, policy evidence, sandbox service
- **cli/** — command registry, app, renderers, command handlers for every workflow group
- **topology/** — providers, resolve, service
- **observability/** — read-only Prometheus/Loki connectors, local OpenTelemetry spans
- **providers/** — builtin, pack, permissions, loader, sandbox, cloud

The import-linter contract enforces: domain has zero IO and no upward imports; agents never import controller modules; nothing below the controller imports the CLI layer. Eleven pre-existing `controller → cli` imports are acknowledged KNOWN DEBT — all function-local, all to dodge import cycles, tracked in `pyproject.toml`.

## 🧪 Tests & checks

```bash
uv sync --group dev          # dev dependencies
uv run pytest                # unit, integration, e2e
uv run ruff check src/ tests/
uv run mypy
uv build --sdist --wheel
```

Test markers: `nightly` (chaos-of-the-chaos tier), `implicit_execution` (opt in to `MAYHEM_ALLOW_IMPLICIT_EXECUTION=1`), `package` (builds and installs the distribution; requires `MAYHEM_PACKAGE_SMOKE=1`).

`tests/unit/test_cli_exhaustive_matrix.py` fails when a registered command is missing from the active CLI surface. `tests/unit/test_release_contract.py` checks the release truth baseline (docs, Justfile, packaging vs. source).

I have not run the test suite in this session, so I can't report pass/fail counts here — run `uv run pytest` yourself to see the current state.

## ⚠ Known limitations

**No kernel or eBPF fault injection.** Mayhem has no eBPF injection, no kernel module, and no in-kernel fault primitive of its own. There is no `bcc`, no `libbpf`, and no eBPF program type anywhere under `src/`. Mayhem loads no code into the kernel and depends on no kernel feature that a stock install does not already provide. The whole injection substrate is userspace plus already-compiled kernel configuration (`tc`/netem configures a qdisc already compiled into the kernel — a traffic-shaping control, not an instrumentation program).

If your failure model lives below the syscall boundary — a specific `write` returning a specific `errno`, a specific page corrupted in a specific process, a specific syscall blocked while the rest of the process stays healthy — Mayhem cannot inject it. That is unsupported, not unimplemented.

**No fault is `verified-live`.** Of the 145 catalog faults, 128 are `verified-unit` and 17 are `experimental`; 0 of 145 are `verified-live`, and none is `stable`. `verified-unit` is a claim about Mayhem's own parameter grammar, refusal path, and compensation contract being deterministic and covered by recorded unit evidence — it says nothing about whether the fault has ever perturbed a running system. `verified-live` is earned only from a recorded live-run record: an injected effect that moved a signal, an undo that actually ran, and a probe that confirmed the pre-injection baseline was restored within tolerance, on the required engines. An empty evidence store yields zero live-verified faults.

**Fault-pack signatures are integrity-checked, not signed.** The pack format carries a `signature: str` and a `signer: str` with no public key, no key id, no algorithm identifier, and no trust store. Mayhem cannot verify a pack signature. What the field holds is an assertion of authorship — the same trust a comment carries. Every pack verdict reports `signature NOT VERIFIED`. What a pack can prove is integrity: `declared_digest` is a SHA-256 over the canonical pack document, checked against the bytes on disk. That detects tampering; it says nothing about who wrote the pack.

**Seventeen catalog entries are `catalog_only`** — defined and planned but refused before mutation, with refusal text naming the missing mechanism (e.g. `app.deadlock`, `clock.freeze`, `fs.read_error`, `mem.oom_kill`, `k8s.image_pull_slow`). They are discoverable rather than hidden: `mayhem discover faults -e FAULT_ID` prints the refusal and the suggested alternative.

**Kubernetes support is layered, not collapsed.** Manifest planning, planner support, executor support, and live resolution are separate states. The legacy `KubernetesAdapter` remains unavailable (a compatibility seam only, `is_available() == False`). Catalog-only Kubernetes faults are not executable merely because they are defined. Possessing one Kubernetes state does not imply the next.

**No backend means no effect.** `start_load`, `stop_load`, and `notify` have no executor yet. They report `acknowledged_no_backend` and the run is not clean — they never look like success.

**No live verification is claimed without a live run.** The capability dashboard reports `live=false` for every row in this repository; `live=true` can only come from a recorded live run.

## ♡ Troubleshooting

| Symptom | Likely cause | Next step |
|---|---|---|
| `mayhem run` refuses before injecting | A safety gate (risk ceiling, concurrency budget, capability gap, missing `--execute`) | Run `mayhem prepare validate` first; read the refusal reason; add `--execute` only when you intend to inject |
| Fault id not found in catalog | Typo or unknown prefix | Use `mayhem discover faults` to list known ids; check the prefix maps to a real category |
| `--compose` not detected | No `docker-compose.yml`/`compose.yml` in cwd | Pass `--compose <path>` explicitly |
| `critical` fault refused at plan time | Missing triple opt-in | Set `policy.allow_critical: true`, add the fault to `policy.critical_fault_acks`, and pass `--allow-critical` |
| Run leaves `DIRTY` state | A compensation/undo failed or lease wasn't released | Run `mayhem recover execute <run-id>` or `mayhem janitor` to sweep orphaned leases |
| `signature NOT VERIFIED` on a pack | Pack format has no trust store | This is expected — verify integrity via `declared_digest` (SHA-256); treat `signature` as an unverified authorship claim |

## License

Proprietary. See `pyproject.toml` for the license declaration.

---

*Built with soft voltage — precise engineering underneath a warm surface. Report gaps between this README and the source; the source is authoritative.*