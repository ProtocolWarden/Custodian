# Backlog

## In Progress

_(none)_

## Up Next

## Recent

- [x] **X-series complete (2026-05-08, on feature/x-series-detectors)**: X1 extended to `.yaml`/`.yml`; X2 added (undeclared cross-repo import via manifest edges); X3 added (stale GitHub URL in docs). 26 new tests; 1005 total passing. cross_repo config already wired in OC / a private downstream repo / SB.

- [x] **Vulture soft-flip + coverage adapter (2026-05-04, on main)**: Vulture default flipped ON with `min_confidence=80` (high-confidence dead code only). New `coverage` adapter at `src/custodian/adapters/coverage.py` ingests externally-produced `coverage.json` and emits `CV1`/`CV2`/`CV3` findings (module unexecuted / function unexecuted / below min coverage). Default OFF in `custodian` CLI — opt-in via `tools.coverage` block. 12 new tests; full Custodian suite 785 pass.

- [x] **T6/T7/T8 — test-presence detector trio (2026-05-04, on main)**: Three new T-class detectors. T6 = src module never imported by any test (file-level companion to T1's symbol-level coverage). T7 = src module has no parallel `test_<name>.py` (convention enforcement; accepts `tests/{unit,integration,contract,regression}/[mirror/]test_<name>.py`). T8 = test file imports nothing from any src package (dangling test detection). All three configurable via `audit.exclude_paths.T6/T7/T8`, `audit.t7_test_dirs`, `audit.t8_exempt`. 20 new tests; full Custodian suite 773 pass.

## Refactor — Master Phase List ✅ ALL 15 PHASES COMPLETE

**Phase 0** ✅ Detector disposition matrix (984c000)
**Phase 1** ✅ Finding model, ToolAdapter ABC, runner.py, package stubs (caadf29)
**Phase 2** ✅ Ruff adapter — JSON parsing, severity prefix map, 23 tests (b5794a0)
**Phase 3** ✅ Deprecated detector flags, --skip-deprecated CLI flag (b5794a0)
**Phase 4** ✅ Semgrep adapter — JSON output parsing, 23 tests (3d8a3cb)
**Phase 5** ⛔ Policy layer (apply_policy / architecture boundary, f69db99) — REMOVED 2026-06-18 as orphan scaffold; superseded by cli/runner.py + detectors/structure.py, never wired into the live path
**Phase 6** ✅ ty adapter (concise format) + mypy adapter (fallback), 28 tests (541e374)
**Phase 7** ✅ Vulture adapter — advisory dead-code, confidence threshold, 18 tests (7187d04)
**Phase 8** ✅ Codemod base — Codemod ABC, run_codemods(), custodian-fix CLI (ebcd026)
**Phase 9** ✅ Config migration — dual-schema loader, DeprecationWarning, custodian-config CLI (0de95cf)
**Phase 10** ✅ Reports — JSON/SARIF/Markdown builders, 25 tests (36230ee)
**Phase 11** ✅ Integration tests — adapter→filter→report pipeline (ed7719a)
**Phase 12** ✅ Deprecated detector cleanup — 27 stub replacements, 325 lines deleted (f287d93)
**Phase 13** ✅ CLI finalization — custodian-report + unified custodian dispatcher (9ec3ea9)
**Phase 14** ✅ Pre-commit integration — .pre-commit-hooks.yaml + local config (05f6336)
**Phase 15** ✅ Multi-repo enhancements — --skip-deprecated, --report-dir (432a58d)

**S4 detector** ✅ tests/conftest.py venv guard check + Custodian's own conftest guard (80b6ea6)

**Repo-level issues remaining**
- A private downstream repo: C9=289 (broad except), D1=~0 (bulk cleared round 9), D3=~40 missing NoReturn, D5=0 (resolved), D6=3 (false positives), D7=35 (keyword-only params, can't rename), F3=11 (MongoDB fields)
- OC: F3=6 (schema/contract fields — mostly false positives), F1=10 dead dataclass fields, C29=6 (long files)
- SB: C19=1 (global _ in logging.py — i18n gettext pattern, acceptable), D5=1 (DecisionSink port class)

## Done (this session — round 9, committed)

_Completed items archived._

## Done (this session — round 8, committed)

_Completed items archived._

## Done (this session — rounds 6–7, committed)

_Completed items archived._

## Done (this session — round 5)

_Completed items archived._

## Done (this session — round 3)

_Completed items archived._

## Done (round 2 — earlier in session)

_Completed items archived._

## Done (round 1 — previous session)

_Completed items archived._

