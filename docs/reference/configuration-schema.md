# Configuration Schema Reference

`tgondi.yaml` — layered, versioned config ([ADR-0008](../adr/0008-layered-versioned-configuration.md)).
Precedence: CLI flags > env vars (`TGONDI_…`) > project `.tgondi/tgondi.yaml` > user
`~/.config/tgondi/tgondi.yaml` > defaults. Merges are deep; lists replace. Every snapshot pins its
resolved source map.

---

## Full schema (v1)

```yaml
apiVersion: tgondi.dev/v1

environment:
  name: staging-lab              # required — part of fingerprint
  class: staging                 # dev | staging | production

controller:
  state_dir: .tgondi             # SQLite + journals + artifacts
  log_level: info

agents:
  ssh:
    hosts: []                    # ["user@bm-1", …]
    key_path: null               # default: agent/ssh defaults
    install_venv_path: /opt/tgondi/venv
    privilege_mode: root_via_systemd   # root_via_systemd | sudo_pinned | unprivileged
    sudo_patterns:               # only for sudo_pinned
      - "^/usr/bin/pkill .*"
  heartbeat_interval: 5s
  dead_after_missed: 3
  idle_ttl: 300s
  lease_watchdog_ttl: 120s

topology:
  compose_file: docker-compose.yaml
  providers: [compose, docker]   # + podman, host_processes
  external_dependency_inference: true

policy:
  allowed_faults:                # allowlist (denylist wins)
    - proc.*
    - cpu.*
    - mem.pressure_gradual
    - net.latency
    - net.partition
    - container.*
    - load.spike
  denied_faults:
    - node.reboot                # forbidden even at critical opt-in unless removed here
  risk_ceiling: high             # low|medium|high|critical
  require_dry_run_first: true
  approval_required_for: [high]  # human gate before execution of plans containing these
  blast_radius:
    max_services_pct: 50
    max_hosts: 2
    max_concurrent_faults: 3
    max_duration_per_fault: 300s
    forbidden_pairs: [[storage.fill, db.conn_exhaust]]
  environments_production_extra: # applied when class == production
    forbid_categories: [storage, node]

toolkit:
  overrides:
    k6: {binary: /usr/local/bin/k6}

maniac:
  enabled: false                 # explicit consent required (spec mandate)
  schedule: "0 3 * * *"          # advisory; scheduler integration is cron-driven
  randomness: balanced           # low | balanced | high
  weights:                       # optional tuning of scoring function
    risk_fit: 1.0
    topology_relevance: 1.0
    novelty: 0.5
    coverage_gap: 0.75

observation:
  redact_patterns:               # merged over built-ins
    - "(?i)(password|secret|token|key)="
  sinks: []                      # future: prometheus, otel, slack
```

## Validation rules

- `apiVersion` must match a supported major; migrations upgrade files explicitly
  (`tgondi config migrate`) — never implicitly ([ADR-0008](../adr/0008-layered-versioned-configuration.md)).
- `maniac.enabled=true` requires `environment.class != production` **or** an explicit
  `allow_maniac_in_production: true` adjacent acknowledgment.
- Unknown keys rejected; enums validated; durations/percentages parsed per DSL rules.
- `policy.risk_ceiling: critical` requires `require_dry_run_first: true`.

## Effective-config inspection

```bash
tgondi config show          # resolved config with source annotations
tgondi config validate      # validate all layers without running anything
```
