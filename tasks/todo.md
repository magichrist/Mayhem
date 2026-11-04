# Mayhem CLI Command Hierarchy Reorganization — Task List (COMPLETE)

All 18 tasks across 6 phases are complete and committed on branch `cli/v2`.

## Phase 1: Foundation — Namespace Package ✅
- [x] Task 1: Create `src/mayhem/cli/namespaces/__init__.py` (package marker) — committed `bca7427`

## Phase 2: Namespace Modules ✅
- [x] Task 2: Create `src/mayhem/cli/namespaces/workspace.py` — committed `9456f7b`
- [x] Task 3: Create `src/mayhem/cli/namespaces/environment.py` — committed `d6a1726`
- [x] Task 4: Create `src/mayhem/cli/namespaces/drill.py` — committed `9456f7b`
- [x] Task 5: Create `src/mayhem/cli/namespaces/runs.py` — committed `9456f7b`
- [x] Task 6: Create `src/mayhem/cli/namespaces/orchestration.py` — committed `9456f7b`
- [x] Task 7: Create `src/mayhem/cli/namespaces/governance.py` — committed `9456f7b`
- [x] Task 8: Create `src/mayhem/cli/namespaces/evidence.py` — committed `9456f7b`
- [x] Task 9: Create `src/mayhem/cli/namespaces/platform.py` — committed `9456f7b`
- [x] Task 10: Create `src/mayhem/cli/namespaces/extensions.py` — committed `9456f7b`
- [x] Task 11: Create `src/mayhem/cli/namespaces/developer.py` — committed `df1cb6c`

## Phase 3: Wire Namespaces into Root App ✅
- [x] Task 12: Modify `command_registry.py` — add `NAMESPACE_SPECS`, `OLD_TO_NEW_PATH`, `register_namespaces` — committed `b05d5d0`
- [x] Task 13: Modify `app.py` — add root-level compatibility aliases for old paths — committed `4e4c4f6`

## Phase 4: Tests ✅
- [x] Task 14: Create `tests/unit/test_cli_namespace_aliases.py` — committed `cd0c7ca`
- [x] Task 15: Create `tests/unit/test_cli_root_help.py` — committed `b97132d`
- [x] Task 16: Create `tests/unit/test_cli_namespace_help.py` — committed `01c8781`
- [x] Test assertion updates for namespaced surface (4 test files) — committed `b83a469`

## Phase 5: Verification Checkpoint ✅
- [x] Task 17: Full CLI smoke test — new paths + old alias paths verified working

## Phase 6: Documentation ✅
- [x] Task 18: Update `docs/CLI-v2.md` and `README.md` — committed `5680c6c`

## Additional ✅
- Remaining namespace modules + plan docs + task list committed `9456f7b`

---

**Plan:** `docs/superpowers/plans/2026-11-04-mayhem-cli-reorganization.md`
**Tasks:** `tasks/todo.md`
**Branch:** `cli/v2`
**All commits:** `bca7427` → `9456f7b` (11 commits)

**Next step:** Fixer agent to run test suite (tests are NOT run by implementation agents per workflow).