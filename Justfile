# ─────────────────────────────────────────────────────────────────────────────
# Mayhem justfile — test every capability against examples/testCase
# ─────────────────────────────────────────────────────────────────────────────
# Usage:  just --list           (show all recipes)
#         just e2e              (full automated run)
#         just smoke            (quick sanity check)

set shell := ["bash", "-euo", "pipefail", "-c"]

_testcase  := "examples/testCase"
_compose   := _testcase / "docker-compose.yml"
_config    := _testcase / "mayhem.yaml"
_spec      := _testcase / "mayhem.yaml"
_db        := ".mayhem/e2e.db"
_workers   := "5"

# ── setup ────────────────────────────────────────────────────────────────────

[private]
setup:
    rm -f {{ _db }}
    mkdir -p .mayhem
    @echo "✓ setup"

# ── topology ─────────────────────────────────────────────────────────────────

# Discover topology from compose + live runtime (containers, processes, services)
topology:
    @echo "=== topology discover ==="
    mayhem discover topology --compose {{ _compose }} | python3 -m json.tool > /dev/null
    @echo "✓ topology discover"

# Topology with prefix shorthand
topology-prefix:
    @echo "=== topology prefix ==="
    mayhem disc topo --compose {{ _compose }} | python3 -m json.tool > /dev/null
    @echo "✓ topology prefix"

# ── toolkit ──────────────────────────────────────────────────────────────────

# List available faults and capabilities (`mayhem discover`)
toolkit:
    @echo "=== toolkit ==="
    mayhem discover faults
    mayhem discover capabilities --json | python3 -m json.tool > /dev/null
    @echo "✓ toolkit"

# ── config ───────────────────────────────────────────────────────────────────

# Show and validate effective config (default + testCase) via `mayhem prepare config`
config:
    @echo "=== config ==="
    mayhem prepare config show --json | python3 -m json.tool > /dev/null
    mayhem --config {{ _config }} prepare config show --json | python3 -m json.tool > /dev/null
    mayhem prepare config validate
    mayhem --config {{ _config }} prepare config validate
    @echo "✓ config"

# ── experiment ───────────────────────────────────────────────────────────────

# Show and validate experiment spec
# Validate the drill spec through the experiment group alias
experiment:
    @echo "=== experiment ==="
    mayhem experiment validate {{ _spec }} --compose {{ _compose }}
    @echo "✓ experiment"

# ── lifecycle: validate → plan → run → status → history → recover ────────────

# Validate spec against live topology (`mayhem prepare validate`)
validate: setup
    @echo "=== validate ==="
    mayhem --db {{ _db }} prepare validate {{ _spec }} --compose {{ _compose }}
    @echo "✓ validate"

# Plan the experiment (`mayhem prepare plan`)
plan:
    @echo "=== plan ==="
    mayhem prepare plan {{ _spec }} --compose {{ _compose }}
    @echo "✓ plan"

# Full run: inject faults, record events, compensate
run: setup
    @echo "=== run ==="
    mayhem --db {{ _db }} run {{ _spec }} --compose {{ _compose }} --execute
    @echo "✓ run"

# Show run status (text + JSON) via `mayhem inspect runs`
status: setup
    @echo "=== status ==="
    mayhem --db {{ _db }} inspect runs
    mayhem --db {{ _db }} inspect runs --json | python3 -m json.tool > /dev/null
    @echo "✓ status"

# Show detailed run history (text + JSON) via `mayhem inspect history`
history:
    @echo "=== history ==="
    @run_id=$$(sqlite3 {{ _db }} "SELECT id FROM runs ORDER BY rowid DESC LIMIT 1" 2>/dev/null || echo ""); \
    if [ -z "$$run_id" ]; then \
        echo "⚠ no runs in DB — skipping history"; \
    else \
        mayhem --db {{ _db }} inspect history "$$run_id"; \
        echo "✓ history"; \
    fi

# Recovery sweep (orphaned fault leases for the most recent run)
recover:
    @echo "=== recover ==="
    @run_id=$$(sqlite3 {{ _db }} "SELECT id FROM runs ORDER BY rowid DESC LIMIT 1" 2>/dev/null || echo ""); \
    if [ -z "$$run_id" ]; then \
        echo "⚠ no runs in DB — skipping recover"; \
    else \
        mayhem --db {{ _db }} recover execute "$$run_id"; \
    fi
    @echo "✓ recover"

# Janitor sweep (stale runs / resources)
janitor: setup
    @echo "=== janitor ==="
    mayhem --db {{ _db }} janitor
    @echo "✓ janitor"

# ── campaign CRUD ────────────────────────────────────────────────────────────

# Create, list, show, start, abort, delete a campaign
campaign: setup
    @echo "=== campaign ==="
    mayhem --db {{ _db }} campaign create "e2e-campaign" --hypothesis "stack survives chaos"
    mayhem --db {{ _db }} campaign list
    @cid=$$(sqlite3 {{ _db }} "SELECT id FROM campaigns WHERE name = 'e2e-campaign' ORDER BY rowid DESC LIMIT 1"); \
    mayhem --db {{ _db }} campaign show "$$cid"; \
    mayhem --db {{ _db }} campaign status "$$cid"; \
    mayhem --db {{ _db }} campaign start "$$cid" || true; \
    mayhem --db {{ _db }} campaign abort "$$cid" || true
    mayhem --db {{ _db }} campaign create "e2e-delete-campaign"
    @delete_cid=$$(sqlite3 {{ _db }} "SELECT id FROM campaigns WHERE name = 'e2e-delete-campaign' ORDER BY rowid DESC LIMIT 1"); \
    mayhem --db {{ _db }} campaign delete --yes "$$delete_cid"
    @echo "✓ campaign"

# ── full round-trip ─────────────────────────────────────────────────────────

# Full lifecycle: validate → plan → run → status → history → recover
full: setup
    @echo "=== full round-trip ==="
    mayhem --db {{ _db }} prepare validate {{ _spec }} --compose {{ _compose }}
    mayhem --db {{ _db }} prepare plan {{ _spec }} --compose {{ _compose }}
    mayhem --db {{ _db }} run {{ _spec }} --compose {{ _compose }} --execute
    mayhem --db {{ _db }} inspect runs
    @run_id=$$(sqlite3 {{ _db }} "SELECT id FROM runs ORDER BY rowid DESC LIMIT 1"); \
    mayhem --db {{ _db }} inspect history "$$run_id"; \
    mayhem --db {{ _db }} recover execute "$$run_id"
    @echo "✓ full round-trip"

# ── stack management ─────────────────────────────────────────────────────────

# Start the testCase compose stack
stack-up:
    @echo "=== stack up ==="
    cd {{ _testcase }} && podman compose up -d 2>/dev/null || docker compose up -d
    @sleep 3
    @echo "✓ stack up"

# Stop the testCase compose stack
stack-down:
    @echo "=== stack down ==="
    cd {{ _testcase }} && podman compose down -v 2>/dev/null || docker compose down -v
    @echo "✓ stack down"

# ── tests ────────────────────────────────────────────────────────────────────

# Run unit tests
test-unit:
    @echo "=== unit tests ==="
    python3 -m pytest tests/unit/ -n {{ _workers }} --dist loadfile -v --tb=short
    @echo "✓ unit tests"

# Run e2e tests (in-process, no containers needed)
test-e2e:
    @echo "=== e2e tests ==="
    python3 -m pytest tests/e2e/ -v --tb=short
    @echo "✓ e2e tests"

# Run all tests
test:
    @echo "=== all tests ==="
    python3 -m pytest tests/ -v --tb=short
    @echo "✓ all tests"

# Run linter
lint:
    @echo "=== lint ==="
    ruff check src/ tests/
    @echo "✓ lint"

# Check the release truth baseline (docs/Justfile/packaging vs. the source)
contract:
    @echo "=== release contract ==="
    python3 -m pytest tests/unit/test_release_contract.py -v --tb=short
    @echo "✓ release contract"

# Build the sdist and wheel
build:
    @echo "=== build ==="
    python3 -m build --sdist --wheel
    @echo "✓ build"

# ── aggregate targets ────────────────────────────────────────────────────────

# Quick smoke: topology + toolkit + config + experiment + validate + plan
smoke: topology toolkit config experiment validate plan
    @echo "✓ smoke"

# Full automated run: stack → topology → config → experiment → full lifecycle → campaign → tests
e2e: stack-up topology toolkit config experiment full campaign test
    @echo ""
    @echo "╔══════════════════════════════════════════════╗"
    @echo "║   ALL E2E RECIPES PASSED                     ║"
    @echo "╚══════════════════════════════════════════════╝"

# ── changelog ─────────────────────────────────────────────────────────────────
# Regenerate CHANGELOG.md from git history (git-cliff)
changelog:
    git-cliff --config cliff.toml -o CHANGELOG.md

# Render notes for the current release only (used as the GitHub release body)
changelog-release:
    git-cliff --config cliff.toml --tag "$$(git describe --tags --abbrev=0)" --strip header
