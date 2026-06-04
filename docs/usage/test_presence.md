# Test-presence detectors — T6 / T7 / T8

T1 and T2 inspect the *shape* of tests you already have (does a public symbol
get referenced? does a test function actually assert?). The **test-presence
trio** answers a different question: **is the src under audit exercised by
tests at all?** Three complementary file-level checks, all LOW-severity
advisory (`custodian_policy`), all configurable.

| Code | What it flags | The gap it closes |
|------|---------------|-------------------|
| **T6** | A src module whose dotted name is never `import`ed by any test file | Import-time blind spots — a module no test ever loads |
| **T7** | A src module with no parallel `test_<name>.py` under `tests/` | Convention drift — files that grew without a sibling test |
| **T8** | A `test_*.py` file whose imports never reach any src package | Dangling tests — they run but don't touch the codebase under audit |

T6 is the file-level companion to T1's symbol-level coverage: a module rich in
re-exports can satisfy T1 (every name appears *somewhere* in tests) yet never
be imported as a unit — T6 catches that. T7 is a pure naming-convention gate.
T8 catches the inverse: a test that exists, runs, asserts, but exercises only
stdlib + helpers and never the src package.

## How each works

### T6 — module never imported by a test

Builds the importable dotted name of every src module
(`src/foo/bar.py` → `foo.bar`, or `<pkg>.foo.bar` when `src_root` itself is a
package), then collects every dotted name referenced by a test `import` /
`from`-import, **prefix-expanded** so `from a.b import x` registers `a`,
`a.b`, and `a.b.x`. Any src module whose dotted name never appears is flagged.
`__init__.py` and dunder files are skipped (a package is implicitly exercised
whenever a submodule is imported — flagging it would double-count). Relative
imports in tests are ignored (they can't reach src).

### T7 — no parallel test file

For `src/foo/bar.py`, any of these counts as a parallel test:

```
tests/test_bar.py                 tests/foo/test_bar.py
tests/unit/test_bar.py            tests/unit/foo/test_bar.py
tests/integration/test_bar.py     tests/integration/foo/test_bar.py
tests/contract/test_bar.py        tests/contract/foo/test_bar.py
tests/regression/test_bar.py      tests/regression/foo/test_bar.py
```

The default sub-dir set is `unit, integration, contract, regression` (plus the
flat `tests/` root and a mirrored sub-path). Add your own with
`audit.t7_test_dirs`. `__init__.py` and dunders are skipped.

### T8 — dangling test

Derives the top-level src package names from `src_root` (both conventions
supported: `src_root` *is* the package, or `src_root` *contains* packages),
then flags `test_*.py` files whose imports never reach any of them.

Two escape hatches keep T8 quiet on legitimate cases:

- **Transitive via conftest.** If a `conftest.py` at or above the test's
  directory imports a src package, the test is considered to touch src — its
  fixtures are visible to the test. Walks ancestors up to `tests_root`.
- **Default-exempt integration dirs.** `tests/integration/**`,
  `tests/e2e/**`, `tests/smoke/**` (and `test/...` variants) are exempt by
  default because they conventionally drive the system via subprocess / HTTP /
  CLI rather than imports. Re-enable with `audit.t8_default_exempt: false`.

`conftest.py` and `__init__.py` are never flagged as dangling tests.

## Configuration

All three work with zero config. Override under the `audit:` block in
`.custodian/config.yaml`:

```yaml
audit:
  # Per-detector path excludes (glob, repo-relative)
  exclude_paths:
    T6:
      - "src/**/_generated/**"      # codegen — no test expected
    T7:
      - "src/**/migrations/**"      # Alembic-style migrations
    T8:
      - "tests/perf/**"             # benchmarks, not unit tests

  # T7 — extra acceptable test sub-directories (added to the defaults)
  t7_test_dirs:
    - acceptance
    - property

  # T8 — extra exempt globs (added to the integration/e2e/smoke defaults)
  t8_exempt:
    - "tests/cli/**"

  # T8 — turn OFF the built-in integration/e2e/smoke exemptions
  t8_default_exempt: false
```

## Worked examples

**T6 — a module no test loads.** `src/app/legacy_export.py` defines
`build_export()`, referenced nowhere in tests by name *or* import:

```
src/app/legacy_export.py: module 'app.legacy_export' not imported by any test file
```

Action: add `from app.legacy_export import build_export` to a test (and assert
on it), or — if the module is genuinely dead — delete it (cross-check with D1 /
Vulture, then `triage` votes DELETE).

**T7 — a file that grew without a sibling test.** A new
`src/app/services/billing.py` shipped with its tests inlined into an unrelated
file:

```
src/app/services/billing.py: no parallel test (expected e.g. tests/unit/services/test_billing.py)
```

Action: create `tests/unit/services/test_billing.py`. If your repo
deliberately co-locates tests under a non-standard dir, add it to
`audit.t7_test_dirs`.

**T8 — a test that doesn't touch src.** `tests/test_helpers_only.py` imports
only `json` and a local fixture helper:

```
tests/test_helpers_only.py: no imports from any src package (app, app_core, app_cli (+2 more))
```

Action: the test isn't exercising the codebase — either point it at real src
code or, if it's a pure helper-of-helpers test, move it under an exempt path
or add it to `audit.t8_exempt`.

## When defaults aren't right

- **Integration tests trip T6/T8.** Tests that exercise src via subprocess
  or HTTP (not imports) legitimately never `import` the package. Put them
  under `tests/integration/**` (T8 default-exempt) or add the path to
  `audit.exclude_paths.T6` / `audit.t8_exempt`.
- **Non-standard test layout trips T7.** If you keep tests in `spec/` or use
  a `_test.py` suffix instead of a `test_` prefix, T7's convention won't
  match. Add the dir to `t7_test_dirs` for the sub-dir case; the
  `test_<name>.py` filename shape itself is fixed (it's the convention being
  enforced).
- **Codegen / migrations.** Generated modules and DB migrations rarely have
  (or need) parallel tests — exclude them per-detector.

## CI gate

All three are LOW / non-blocking by default. To gate merges on a clean count:

```yaml
audit:
  blocking:
    - T7   # every src module must have a sibling test
    # T6 / T8 are commonly left advisory — import-graph reachability and
    # dangling-test heuristics carry a higher false-positive rate.
```

## What this is not

- **Not a coverage tool.** T6/T7/T8 are *static* — they read imports and
  filenames, not execution. For runtime "was this line actually run?" use the
  coverage adapter (CV1/CV2/CV3, see `docs/usage/coverage_adapter.md`).
- **Not a guarantee of good tests.** T7 is satisfied by an empty
  `test_bar.py`; pair it with T2 (no-assertion test) for substance.
- **Not symbol-level.** A module that's imported but whose individual
  functions go untested still passes T6 — that's T1's job.
