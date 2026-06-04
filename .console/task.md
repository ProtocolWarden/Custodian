# Task

## Objective

Continue expanding Custodian's detector coverage and run improvement rounds across all repos until findings reach zero or are explicitly deferred.

## Context

Current state (2026-05-02):

**70 detectors live** (57 core + 13 OC plugin):
- C-class (C1–C33): file-local code health, security, complexity, ghost-work density
- S-class (S1–S4): import layer violations, circular imports, test import in src, conftest venv guard
- U-class (U1–U3): raise NIE / ellipsis / docstring-only stubs
- D-class (D1–D7): dead functions, branches, classes, unreachable code, fields, partially-wired pipelines, dead method params
- F-class (F1–F3): dead dataclass fields, module constants, Pydantic BaseModel fields
- A-class (A1–A2): declarative invariants (max_lines/max_classes/forbidden_import, directory structure)
- E/T/X/G/I: annotation gaps, test shape, complexity, ghost CamelCase, unused imports
- H1: hexagonal architecture layer ordering

All 15 refactor phases complete. Custodian self-audit: 0 findings.

Remaining findings across managed repos (as of round 9):
- A private downstream repo: A1=1 (WorkflowContext 47 fields, real architectural debt), T1=670 (integration-tested pipeline, intentional), VULTURE=~342, C15=163 (tracked tech debt)
- OC: T1=266 (excluded adapters/entrypoints, monkeypatch-tested)
- SB: clean
- CxRP: clean
- OConsole: clean

## Definition of Done

Each new detector: implemented with tests, running clean on all 5 repos, committed and pushed.
Each improvement round: all fixable findings resolved, non-fixable deferred with rationale.
