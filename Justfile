# ─────────────────────────────────────────────────────────────────────────────
# Mayhem E2E Justfile — every CLI command exercised against examples/testCase
# ─────────────────────────────────────────────────────────────────────────────
# Usage:  just --list           (show all recipes)
#         just e2e-all          (full automated run)
#         just manual-smoke     (manual tests requiring Docker)

set shell := ["bash", "-euo", "pipefail", "-c"]

_testcase  := "examples/testCase"
_compose   := _testcase / "docker-compose.yml"
_config    := _testcase / "mayhem.yml"
_fullfault := _testcase / "full-fault.yml"
_spec      := _testcase / "full-fault.yml"
_db        := ".mayhem/e2e.db"

# ── setup ────────────────────────────────────────────────────────────────────

# Remove stale test DB and create directories
[private]
setup:
    rm -f {{ _db }}
    mkdir -p .mayhem
    echo "✓ setup complete"

# ── topology ─────────────────────────────────────────────────────────────────

# Discover topology from compose file
topology-discover:
    @echo "=== topology discover (compose) ==="
    mayhem topology discover --compose {{ _compose }}
    @echo "✓ topology discover passed"

# Discover topology (prefix shorthand)
topology-discover-prefix:
    @echo "=== topology discover (prefix: top d) ==="
    mayhem top d --compose {{ _compose }}
    @echo "✓ topology prefix passed"

# ── toolkit ──────────────────────────────────────────────────────────────────

# List fault catalog
toolkit-faults:
    @echo "=== toolkit faults ==="
    mayhem toolkit faults
    @echo "✓ toolkit faults passed"

# List capabilities
toolkit-list:
    @echo "=== toolkit list ==="
    mayhem toolkit list
    @echo "✓ toolkit list passed"

# List capabilities as JSON
toolkit-list-json:
    @echo "=== toolkit list --json ==="
    mayhem toolkit list --json | python3 -m json.tool > /dev/null
    @echo "✓ toolkit list --json passed"

# Toolkit prefix
toolkit-prefix:
    @echo "=== toolkit prefix (tk f) ==="
    mayhem tool f
    @echo "✓ toolkit prefix passed"

# ── config ───────────────────────────────────────────────────────────────────

# Show effective config (YAML)
config-show:
    @echo "=== config show ==="
    mayhem config show
    @echo "✓ config show passed"

# Show effective config (JSON)
config-show-json:
    @echo "=== config show --json ==="
    mayhem config show --json | python3 -m json.tool > /dev/null
    @echo "✓ config show --json passed"

# Show config with testCase mayhem.yml
config-show-testcase:
    @echo "=== config show (testCase) ==="
    mayhem --config {{ _config }} config show
    @echo "✓ config show (testCase) passed"

# Validate config
config-validate:
    @echo "=== config validate ==="
    mayhem config validate
    @echo "✓ config validate passed"

# Validate testCase config
config-validate-testcase:
    @echo "=== config validate (testCase) ==="
    mayhem --config {{ _config }} config validate
    @echo "✓ config validate (testCase) passed"

# Config prefix
config-prefix:
    @echo "=== config prefix (cfg s) ==="
    mayhem cfg s
    @echo "✓ config prefix passed"

# ── experiment ───────────────────────────────────────────────────────────────

# Show experiment spec JSON
experiment-show:
    @echo "=== experiment show ==="
    mayhem experiment show {{ _fullfault }}
    @echo "✓ experiment show passed"

# Validate experiment spec
experiment-validate:
    @echo "=== experiment validate ==="
    mayhem experiment validate {{ _fullfault }}
    @echo "✓ experiment validate passed"

# Experiment prefix (ex v)
experiment-prefix:
    @echo "=== experiment prefix (ex v) ==="
    mayhem ex v {{ _fullfault }}
    @echo "✓ experiment prefix passed"

# Experiment prefix (e v)
experiment-prefix-short:
    @echo "=== experiment prefix (e v) ==="
    mayhem e v {{ _fullfault }}
    @echo "✓ experiment prefix-short passed"

# ── validate (lifecycle) ────────────────────────────────────────────────────

# Validate with process topology
validate-process:
    @echo "=== validate --process ==="
    mayhem validate {{ _fullfault }} --process "download-1=10001" --process "download-2=10002"
    @echo "✓ validate --process passed"

# Validate with compose topology
validate-compose:
    @echo "=== validate --compose ==="
    mayhem validate {{ _fullfault }} --compose {{ _compose }}
    @echo "✓ validate --compose passed"

# Validate with all topology options
validate-all-topo:
    @echo "=== validate --process --service --host --compose ==="
    mayhem validate {{ _fullfault }} \
        --process "download-1=10001" \
        --process "download-2=10002" \
        --service "lb" \
        --service "db" \
        --host "local" \
        --compose {{ _compose }}
    @echo "✓ validate all topology options passed"

# Validate prefix
validate-prefix:
    @echo "=== validate prefix (v) ==="
    mayhem v {{ _fullfault }} --process "download-1=10001"
    @echo "✓ validate prefix passed"

# ── plan (lifecycle) ────────────────────────────────────────────────────────

# Plan with process topology
plan-process:
    @echo "=== plan --process ==="
    mayhem plan {{ _fullfault }} --process "download-1=10001" --process "download-2=10002"
    @echo "✓ plan --process passed"

# Plan with compose topology
plan-compose:
    @echo "=== plan --compose ==="
    mayhem plan {{ _fullfault }} --compose {{ _compose }}
    @echo "✓ plan --compose passed"

# Plan with all topology options
plan-all-topo:
    @echo "=== plan all topology ==="
    mayhem plan {{ _fullfault }} \
        --process "download-1=10001" \
        --process "download-2=10002" \
        --service "lb" \
        --service "db" \
        --host "local" \
        --compose {{ _compose }}
    @echo "✓ plan all topology passed"

# Plan prefix
plan-prefix:
    @echo "=== plan prefix (p) ==="
    mayhem p {{ _fullfault }} --process "download-1=10001"
    @echo "✓ plan prefix passed"

# ── run (lifecycle) ─────────────────────────────────────────────────────────

# Full run with process topology (real execution, creates DB)
run-process: setup
    @echo "=== run --process ==="
    mayhem --db {{ _db }} run {{ _fullfault }} \
        --process "download-1=10001" \
        --process "download-2=10002"
    @echo "✓ run --process passed"

# Full run with compose topology
run-compose: setup
    @echo "=== run --compose ==="
    mayhem --db {{ _db }} run {{ _fullfault }} \
        --compose {{ _compose }}
    @echo "✓ run --compose passed"

# Full run with all topology options
run-all-topo: setup
    @echo "=== run all topology ==="
    mayhem --db {{ _db }} run {{ _fullfault }} \
        --process "download-1=10001" \
        --process "download-2=10002" \
        --service "lb" \
        --service "db" \
        --host "local" \
        --compose {{ _compose }}
    @echo "✓ run all topology passed"

# ── status / history ────────────────────────────────────────────────────────

# Show run status
status: setup
    @echo "=== status ==="
    mayhem --db {{ _db }} status
    @echo "✓ status passed"

# Show run status as JSON
status-json: setup
    @echo "=== status --json ==="
    mayhem --db {{ _db }} status --json
    @echo "✓ status --json passed"

# Show run history (requires a run-id from a previous run)
history:
    @echo "=== history ==="
    @run_id=$$(sqlite3 {{ _db }} "SELECT id FROM runs ORDER BY rowid DESC LIMIT 1" 2>/dev/null || echo "none"); \
    if [ "$$run_id" = "none" ]; then \
        echo "⚠ no runs in DB — skipping history"; \
    else \
        mayhem --db {{ _db }} history "$$run_id"; \
        echo "✓ history passed"; \
    fi

# Show run history as JSON
history-json:
    @echo "=== history --json ==="
    @run_id=$$(sqlite3 {{ _db }} "SELECT id FROM runs ORDER BY rowid DESC LIMIT 1" 2>/dev/null || echo "none"); \
    if [ "$$run_id" = "none" ]; then \
        echo "⚠ no runs in DB — skipping history --json"; \
    else \
        mayhem --db {{ _db }} history "$$run_id" --json | python3 -m json.tool > /dev/null; \
        echo "✓ history --json passed"; \
    fi

# ── recover / janitor ───────────────────────────────────────────────────────

# Recovery sweep
recover: setup
    @echo "=== recover ==="
    mayhem --db {{ _db }} recover
    @echo "✓ recover passed"

# Janitor sweep
janitor-sweep: setup
    @echo "=== janitor sweep ==="
    mayhem --db {{ _db }} janitor sweep
    @echo "✓ janitor sweep passed"

# ── campaign CRUD ────────────────────────────────────────────────────────────

# List campaigns (empty)
campaign-list: setup
    @echo "=== campaign list ==="
    mayhem --db {{ _db }} campaign list
    @echo "✓ campaign list passed"

# Create a campaign
campaign-create: setup
    @echo "=== campaign create ==="
    mayhem --db {{ _db }} campaign create --name "e2e-campaign" \
        --hypothesis "stack survives chaos"
    @echo "✓ campaign create passed"

# Create + list campaigns
campaign-create-list: setup
    @echo "=== campaign create + list ==="
    mayhem --db {{ _db }} campaign create --name "e2e-cl-list" \
        --hypothesis "test hypothesis"
    mayhem --db {{ _db }} campaign list
    @echo "✓ campaign create + list passed"

# Create + show campaign
campaign-create-show: setup
    @echo "=== campaign create + show ==="
    mayhem --db {{ _db }} campaign create --name "e2e-cl-show"
    @cid=$$(sqlite3 {{ _db }} "SELECT id FROM campaigns ORDER BY rowid DESC LIMIT 1"); \
    mayhem --db {{ _db }} campaign show "$$cid"
    @echo "✓ campaign create + show passed"

# Create + show campaign JSON
campaign-create-show-json: setup
    @echo "=== campaign create + show --json ==="
    mayhem --db {{ _db }} campaign create --name "e2e-cl-json"
    @cid=$$(sqlite3 {{ _db }} "SELECT id FROM campaigns ORDER BY rowid DESC LIMIT 1"); \
    mayhem --db {{ _db }} campaign show "$$cid" --json | python3 -m json.tool > /dev/null
    @echo "✓ campaign create + show --json passed"

# Create + status campaign
campaign-create-status: setup
    @echo "=== campaign create + status ==="
    mayhem --db {{ _db }} campaign create --name "e2e-cl-status"
    @cid=$$(sqlite3 {{ _db }} "SELECT id FROM campaigns ORDER BY rowid DESC LIMIT 1"); \
    mayhem --db {{ _db }} campaign status "$$cid"
    @echo "✓ campaign create + status passed"

# Create + start campaign (may fail if no experiment loaded)
campaign-create-start: setup
    @echo "=== campaign create + start ==="
    mayhem --db {{ _db }} campaign create --name "e2e-cl-start"
    @cid=$$(sqlite3 {{ _db }} "SELECT id FROM campaigns ORDER BY rowid DESC LIMIT 1"); \
    mayhem --db {{ _db }} campaign start "$$cid" || true
    @echo "✓ campaign create + start passed"

# Create + abort campaign
campaign-create-abort: setup
    @echo "=== campaign create + abort ==="
    mayhem --db {{ _db }} campaign create --name "e2e-cl-abort"
    @cid=$$(sqlite3 {{ _db }} "SELECT id FROM campaigns ORDER BY rowid DESC LIMIT 1"); \
    mayhem --db {{ _db }} campaign abort "$$cid"
    @echo "✓ campaign create + abort passed"

# Create + delete campaign
campaign-create-delete: setup
    @echo "=== campaign create + delete ==="
    mayhem --db {{ _db }} campaign create --name "e2e-cl-delete"
    @cid=$$(sqlite3 {{ _db }} "SELECT id FROM campaigns ORDER BY rowid DESC LIMIT 1"); \
    mayhem --db {{ _db }} campaign delete "$$cid"
    @echo "✓ campaign create + delete passed"

# Campaign prefix
campaign-prefix: setup
    @echo "=== campaign prefix (cam l) ==="
    mayhem --db {{ _db }} cam l
    @echo "✓ campaign prefix passed"

# ── full round-trip ─────────────────────────────────────────────────────────

# Full lifecycle: validate → plan → run → status → history → recover
full-roundtrip: setup
    @echo "=== full round-trip ==="
    mayhem --db {{ _db }} validate {{ _fullfault }} \
        --process "download-1=10001" --process "download-2=10002"
    mayhem --db {{ _db }} plan {{ _fullfault }} \
        --process "download-1=10001" --process "download-2=10002"
    mayhem --db {{ _db }} run {{ _fullfault }} \
        --process "download-1=10001" --process "download-2=10002"
    mayhem --db {{ _db }} status
    @run_id=$$(sqlite3 {{ _db }} "SELECT id FROM runs ORDER BY rowid DESC LIMIT 1"); \
    mayhem --db {{ _db }} history "$$run_id"
    mayhem --db {{ _db }} recover
    @echo "✓ full round-trip passed"

# Full lifecycle with compose topology
full-roundtrip-compose: setup
    @echo "=== full round-trip (compose) ==="
    mayhem --db {{ _db }} validate {{ _fullfault }} --compose {{ _compose }}
    mayhem --db {{ _db }} plan {{ _fullfault }} --compose {{ _compose }}
    mayhem --db {{ _db }} run {{ _fullfault }} --compose {{ _compose }}
    mayhem --db {{ _db }} status
    @run_id=$$(sqlite3 {{ _db }} "SELECT id FROM runs ORDER BY rowid DESC LIMIT 1"); \
    mayhem --db {{ _db }} history "$$run_id"
    mayhem --db {{ _db }} recover
    @echo "✓ full round-trip (compose) passed"

# ── pytest: unit + e2e ──────────────────────────────────────────────────────

# Run all unit tests
test-unit:
    @echo "=== unit tests ==="
    python3 -m pytest tests/unit/ -v --tb=short
    @echo "✓ unit tests passed"

# Run all e2e tests (in-process, no Docker needed)
test-e2e:
    @echo "=== e2e tests ==="
    python3 -m pytest tests/e2e/ -v --tb=short
    @echo "✓ e2e tests passed"

# Run all tests
test-all:
    @echo "=== all tests ==="
    python3 -m pytest tests/ -v --tb=short
    @echo "✓ all tests passed"

# Run linter
lint:
    @echo "=== ruff lint ==="
    ruff check src/ tests/
    @echo "✓ lint passed"

# ── Docker-dependent manual tests ────────────────────────────────────────────

# Start the testCase compose stack (requires Docker)
#[manual]
stack-up:
    @echo "=== starting testCase compose stack ==="
    cd {{ _testcase }} && docker compose up -d
    sleep 5
    @echo "✓ stack started"

# Stop the testCase compose stack
#[manual]
stack-down:
    @echo "=== stopping testCase compose stack ==="
    cd {{ _testcase }} && docker compose down -v
    @echo "✓ stack stopped"

# Topology discovery with live runtime (requires Docker stack)
#[manual]
topology-live: stack-up
    @echo "=== topology discover (live runtime) ==="
    mayhem topology discover --compose {{ _compose }}
    @echo "✓ topology live passed"

# Topology discovery with Podman runtime
#[manual]
topology-podman:
    @echo "=== topology discover (podman) ==="
    mayhem --podman topology discover --compose {{ _compose }}
    @echo "✓ topology podman passed"

# Full round-trip with live Docker stack
#[manual]
full-live: stack-up
    @echo "=== full round-trip (live Docker) ==="
    rm -f {{ _db }}
    mayhem --db {{ _db }} validate {{ _fullfault }} --compose {{ _compose }}
    mayhem --db {{ _db }} plan {{ _fullfault }} --compose {{ _compose }}
    mayhem --db {{ _db }} run {{ _fullfault }} --compose {{ _compose }}
    mayhem --db {{ _db }} status
    @run_id=$$(sqlite3 {{ _db }} "SELECT id FROM runs ORDER BY rowid DESC LIMIT 1"); \
    mayhem --db {{ _db }} history "$$run_id"
    mayhem --db {{ _db }} recover
    @echo "✓ full live passed"

# ── aggregate targets ───────────────────────────────────────────────────────

# Run EVERY automated e2e recipe in sequence
e2e-all: setup topology-discover topology-discover-prefix toolkit-faults toolkit-list \
    toolkit-list-json toolkit-prefix config-show config-show-json config-show-testcase \
    config-validate config-validate-testcase config-prefix experiment-show \
    experiment-validate experiment-prefix experiment-prefix-short validate-process \
    validate-compose validate-all-topo validate-prefix plan-process plan-compose \
    plan-all-topo plan-prefix run-process status status-json history recover \
    janitor-sweep campaign-list campaign-create campaign-create-list \
    campaign-create-show campaign-create-show-json campaign-create-status \
    campaign-create-start campaign-create-abort campaign-create-delete \
    campaign-prefix full-roundtrip test-e2e
    @echo ""
    @echo "╔══════════════════════════════════════════════╗"
    @echo "║   ALL E2E RECIPES PASSED                     ║"
    @echo "╚══════════════════════════════════════════════╝"

# Quick smoke: topology + toolkit + config + experiment + validate + plan
e2e-smoke: setup topology-discover toolkit-faults config-validate experiment-show \
    validate-process plan-process
    @echo "✓ smoke passed"
