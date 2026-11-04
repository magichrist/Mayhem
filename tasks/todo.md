# Mayhem CLI Command Hierarchy Reorganization — Task List

## Phase 1: Foundation — Namespace Package

- [ ] Task 1: Create `src/mayhem/cli/namespaces/__init__.py` (package marker)
- [ ] Task 2: Create `src/mayhem/cli/namespaces/workspace.py`
- [ ] Task 3: Create `src/mayhem/cli/namespaces/environment.py`
- [ ] Task 4: Create `src/mayhem/cli/namespaces/drill.py`
- [ ] Task 5: Create `src/mayhem/cli/namespaces/runs.py`
- [ ] Task 6: Create `src/mayhem/cli/namespaces/orchestration.py`
- [ ] Task 7: Create `src/mayhem/cli/namespaces/governance.py`
- [ ] Task 8: Create `src/mayhem/cli/namespaces/evidence.py`
- [ ] Task 9: Create `src/mayhem/cli/namespaces/platform.py`
- [ ] Task 10: Create `src/mayhem/cli/namespaces/extensions.py`
- [ ] Task 11: Create `src/mayhem/cli/namespaces/developer.py`

## Phase 3: Wire Namespaces into Root App

- [ ] Task 12: Modify `command_registry.py` — add `NAMESPACE_SPECS`, `OLD_TO_NEW_PATH`, `register_namespaces`
- [ ] Task 13: Modify `app.py` — add root-level compatibility aliases for old paths

## Phase 4: Tests

- [ ] Task 14: Create `tests/unit/test_cli_namespace_aliases.py`
- [ ] Task 15: Create `tests/unit/test_cli_root_help.py`
- [ ] Task 16: Create `tests/unit/test_cli_namespace_help.py`

## Phase 5: Verification Checkpoint

- [ ] Task 17: Full CLI smoke test (existing tests + new paths + old alias paths)

## Phase 6: Documentation

- [ ] Task 18: Update `docs/CLI-v2.md` and `README.md` command examples

---

**Plan saved to:** `docs/superpowers/plans/2026-11-04-mayhem-cli-reorganization.md`

**Total tasks:** 18
**Estimated size:** Medium-L (spans 10+ new files + modifications to 2 existing files + test files)

**Execution options:**
1. Subagent-Driven (recommended) — dispatch fresh subagent per task
2. Inline Execution — execute in this session with checkpoints