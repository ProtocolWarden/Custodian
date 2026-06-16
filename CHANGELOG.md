# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- DC9 — index-coverage detector: docs in `doc_conventions.dc9_index_dirs`
  must be cited from `docs/README.md`. Closes the DC7 escape hatch where a
  sibling-linked doc is no orphan yet missing from the canonical index.
  Opt-in (silent when the config key is unset), DC6 precedent.
- 2026-06-04: reconciled `refactor-phases-0-15` — Refactor master phase list — all 15 phases + S4 detector (history archived).
- 2026-06-04: reconciled `detectors-t6-t8` — T6/T7/T8 — test-presence detector trio (history archived).
- 2026-06-04: reconciled `detector-x3-stale-github-url` — X3 — stale GitHub URL in docs (X-series: X1 yaml-scan, X2 cross-repo import, X3) (history archived).
- 2026-06-04: reconciled `coverage-adapter-cv1-cv3` — Coverage adapter — CV1/CV2/CV3 + Vulture soft-flip ON (history archived).
- 2026-06-04: reconciled `b-class-private-repo-names` — B1 — private-repo-name leakage detector (history archived).
- 2026-06-04: reconciled `triage-layer` — Triage layer — per-file action verdicts (DELETE/IMPLEMENT/WIRE/REDESIGN/CLEANUP) (history archived).
- 2026-06-04: reconciled `tool-first-enforcement` — Tool-first enforcement — deprecate natives covered by Ruff/Vulture/ty, skip_deprecated default (history archived).
- 2026-06-04: reconciled `m-class-repo-meta` — M1–M5 — repo-meta (CHANGELOG/CONTRIBUTING/SECURITY/LICENSE) + CHANGELOG format (history archived).
- 2026-06-04: reconciled `w-class-workspace` — W1–W6 — workspace/.console + hook-wiring + env-contract detectors (history archived).
- 2026-06-04: reconciled `repograph-governance-arch` — ARCH1–ARCH4 RepoGraph governance gate + public-surface catalog policy (history archived).
- 2026-06-16: reconciled `refactor-phases-0-15` — Refactor master phase list — all 15 phases + S4 detector (history archived).
- 2026-06-16: reconciled `detectors-t6-t8` — T6/T7/T8 — test-presence detector trio (history archived).
- 2026-06-16: reconciled `detector-x3-stale-github-url` — X3 — stale GitHub URL in docs (X-series: X1 yaml-scan, X2 cross-repo import, X3) (history archived).
- 2026-06-16: reconciled `dc-class-doc-conventions` — DC1–DC8 — doc-convention detectors (promoted from OC plugin) (history archived).
- 2026-06-16: reconciled `tool-first-enforcement` — Tool-first enforcement — deprecate natives covered by Ruff/Vulture/ty, skip_deprecated default (history archived).
- 2026-06-16: reconciled `w-class-workspace` — W1–W6 — workspace/.console + hook-wiring + env-contract detectors (history archived).
