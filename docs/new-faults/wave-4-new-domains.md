# Wave 4 — the 21 invalid prefixes: new domains, or no domain at all

21 of the 72 requested ids use a prefix that has no `FaultCategory`. The
mechanism is rejected before the model is even built:
`FaultCategory.from_fault_id` raises `SchemaValidationError` for an unknown
prefix (`domain/faults.py:41-51`).

**Recommendation: do not add any of the seven prefixes.** Reuse the existing
namespaces, and for the two genuinely new domains (`mq`, `obs`) decide
explicitly whether to build a substrate or refuse.

## 4.1 Why adding a prefix is not one line

Adding a `FaultCategory` member requires entries in **three total maps** keyed
by category, or `_define` raises `KeyError` at import:

- `_FAILURE_DOMAIN_BY_CATEGORY` (`catalog.py:56-74`)
- `_EFFECT_BY_CATEGORY` (`catalog.py:115-133`)
- `_VERIFICATION_BY_CATEGORY` (`catalog.py:95-113`)

Plus `_PREFIX_TO_CATEGORY` (`faults.py:54-76`), and
`test_every_category_is_represented` (`test_fault_catalog_exhaustive.py:784-785`)
asserts `{d.category for d in CATALOG} == frozenset(FaultCategory)` — so a new
category with no fault fails just as hard as a fault with no category.

`VerificationMethod` (`faults.py:117-127`) is also a closed enum of 10 values.
A new category must reuse one: there is no `VerificationMethod.MESSAGE_QUEUE`
or `OBSERVABILITY`. That is a strong signal these are not natural categories in
this model.

## 4.2 `cluster.` (5 ids) — reject the prefix, use `k8s.`

There is no Raft/etcd/consensus client in the dependency set (`pydantic`,
`typer`, `click`, `pyyaml`, `structlog`, `kubernetes`). The `kubernetes` client
is a CRUD API, not a leader-election controller.

| requested | closest existing k8s fault | note |
| --- | --- | --- |
| `cluster.split_brain` | `k8s.node_network_partition(direction=both)` | partitions the CNI into two halves via an `MH-PARTITION` iptables chain dropping the service CIDR and `8472` (`executors.py:3238-3246`) — observably split-brain |
| `cluster.state_stale` | `k8s.workload_stall(stall_s='30s')` | pods keep running but state stops advancing |
| `cluster.leader_loss` | `k8s.pod_kill` on the leader | needs a leader-elector to identify; mayhem does not model roles |
| `cluster.replication_lag` | `k8s.replica_reduce` + `k8s.network_policy` | composable today; a dedicated id adds nothing |
| `cluster.election_delay` | — | no primitive. Would be a `catalog_only` even in the k8s lane. |

Note `cluster.replication_lag` also duplicates the requested `db.replication_lag`
— two ids for one mechanism. Pick one namespace.

## 4.3 `config.` / `secret.` / `cert.` / `auth.` (5 ids) — reject all four prefixes

Every mechanism already exists under the right namespace:

| requested | use instead | why |
| --- | --- | --- |
| `config.invalid` | `k8s.configmap_corrupt` | patches every ConfigMap key to `f"{prefix}{value[:120]}"` with snapshot restore (`executors.py:2742-2768`) |
| `config.missing` | `k8s.secret_unavailable` | deletes the Secret and recreates it from a pod annotation on undo (`executors.py:2769-2850`) — the same delete/annotate/recreate shape works for a ConfigMap |
| `secret.expired` | `tls.certificate_expired` | truncates `/etc/ssl/certs/ca-certificates.crt` so trust validation fails, restores the file (`compensation.py:2220-2250`) |
| `cert.revoked` | `tls.handshake_failure` | revocation is the same trust-store concern as expiry; both `tls.*` |
| `auth.denied` | `http.error_injection{status:401\|403}` | the mechanism exists today; `status` is unbounded and `canned()` clamps only at `>= 100` |

**If a ConfigMap-*missing* fault is wanted** (distinct from
`k8s.configmap_corrupt`), add `k8s.configmap_unavailable` by reusing the
`K8sConfigExecutor` delete/annotate/recreate path. That is a real gap and a
cheap fill — but it belongs in the `k8s.` namespace.

## 4.4 `mq.` (7 ids) — a substrate decision, not a catalog decision

No broker client exists: zero hits for `pika`, `kafka-python`,
`confluent-kafka`, or any AMQP/Kafka protocol handling. Message *semantics* —
ack, publish failure, consumer lag, poison messages — are unreachable from L4.

What exists is the **L4 shadow**, and it is already good:

| requested | L4 equivalent that works today |
| --- | --- |
| `mq.message_loss` | `net.packet_loss{percent:100}` |
| `mq.duplicate` | `net.duplicate(percent, direction)` → `tc netem duplicate <p>%` (`compensation.py:1071-1082`) |
| `mq.consume_delay` | `net.latency` / `dependency.timeout` |
| `mq.publish_failure` | `dependency.block(port, protocol)` / `net.connection_refuse` |
| `mq.consumer_lag`, `mq.ack_delay`, `mq.poison_message` | **no equivalent** — these are broker-internal state |

Three options:

1. **(recommended) Refuse all seven as `catalog_only`** under a new
   `FaultCategory.MESSAGING`, with refusals that name the L4 equivalent where
   one exists. This costs one new category, the three map entries, and 7
   `catalog_only` entries — and it makes the gap discoverable via
   `mayhem discover faults`, which is the entire point of a catalog.
2. **Add a broker dependency** (`pika` or `confluent-kafka`) and implement the
   three unreachable ids. This is a real dependency-policy decision: mayhem's
   current dependency set is deliberately small and generic, and `import-linter`
   already forbids `socket`/`subprocess`/`asyncio` from `mayhem.domain`. A
   broker client in the domain layer would violate that layering.
3. **Build a broker-protocol proxy** (the toxiproxy route). Note
   `src/mayhem/toolkit/manifests/toxiproxy.yaml` **already exists** and
   declares `net.latency`/`net.partition`, but grep confirms **no executor or
   compensation path references toxiproxy** — it is capability-negotiation
   metadata only, plus a `ResourceType.TOXIPROXY_TOXIC` in
   `resource_manager.py:445`. Wiring toxiproxy is a plausible path to real
   `mq.*` faults, and it is a substantial but well-scoped project.

If wave 2's proxy work lands, that same in-container HTTP proxy is the natural
home for a subset of `mq.*` (publish failure, consume delay) — but only for
HTTP-based brokers, and it would be dishonest to call that general MQ coverage.

## 4.5 `obs.` (4 ids) — the interesting reframing

The literal request — make the target's logs, metrics, and traces disappear —
has no mechanism, and never will from outside: mayhem would have to perturb the
target's collector, and mayhem does not know how that collector is deployed.

But there is a genuinely useful fault hiding here, and it is testable **today**:

> `obs.*` should break **mayhem's own** observation path, not the target's
> telemetry pipeline.

Mayhem's observation sources are real, configured per drill
(`observability.sources` in the spec — `kind: logs`, `kind: probe`, with
`cadence`, `tail`, `timeout`). The run already assembles a verdict from those
observations (`expected_evidence` includes `observations` and `verdict`).

So the honest, valuable version of `obs.logs_drop` / `obs.metrics_drop` /
`obs.trace_drop` / `obs.log_delay` is: **"the drill still produces a correct
verdict when its evidence is missing or stale."** That is a fault of mayhem's
own evidence pipeline, it needs no target cooperation, and it tests something
that matters — a chaos tool that silently degrades to a green verdict when it
cannot see is worse than no tool.

Proposed semantics:

| id | mechanism | verification |
| --- | --- | --- |
| `obs.logs_drop` | suppress the `kind: logs` sources for the drill | the run reaches a verdict and records the suppression; evidence still contains `verdict` |
| `obs.log_delay` | delay log sources past their `timeout_s` | same |
| `obs.metrics_drop` | suppress metric sources | same |
| `obs.trace_drop` | suppress trace sources | same |

This is a **different product decision**, not a catalog addition: it changes
what a verdict means when evidence is incomplete. It should be an ADR, not a
fault entry, and the fault should only follow once the semantics are settled.
Recommendation: take it to an ADR in a follow-up; do **not** put it in this
plan's waves.

## 4.6 Wave 4 summary

| prefix | ids | action | cost |
| --- | --- | --- | --- |
| `cluster.` | 5 | reject prefix; map to `k8s.*` twins; `cluster.election_delay` is `catalog_only` even there | low |
| `config.` | 2 | reject prefix; map to `k8s.configmap_corrupt` / `secret_unavailable`; optionally add `k8s.configmap_unavailable` | low |
| `secret.` | 1 | reject prefix; map to `tls.certificate_expired` | trivial |
| `cert.` | 1 | reject prefix; map to `tls.handshake_failure` | trivial |
| `auth.` | 1 | reject prefix; map to `http.error_injection{status:401}` | trivial |
| `mq.` | 7 | ADR: refuse as `catalog_only` under a new MESSAGING category, or build the toxiproxy substrate | medium |
| `obs.` | 4 | ADR: reframe as a mayhem-evidence-integrity fault, or refuse | medium |

**Net: 21 requested ids produce 0-1 new fault ids and 1-2 ADRs.** That is the
honest answer. The value of these requests is that they expose three real gaps
in the catalog — no MQ substrate, no observability substrate, and no
consensus substrate — and those are projects, not parameters.
