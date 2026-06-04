# Coverage adapter — CV1 / CV2 / CV3

Custodian's static detectors (D1, D5, Vulture) reason about whether code is
*reachable*. The **coverage adapter** adds the orthogonal, runtime signal:
**was this code actually executed?** It does not run `coverage.py` itself —
running coverage means running the consumer's production pipeline, which is
repo-specific. Instead it **ingests a `coverage.json`** produced externally
(typically by the consuming repo's own end-to-end audit hook) and normalizes
it into the standard `Finding` shape, exactly like the Ruff / Semgrep /
Vulture adapters.

Module: `src/custodian/adapters/coverage.py` (class `CoverageAdapter`).
Default **OFF** in the standalone `custodian` CLI — opt in explicitly.

| Code | What it means | Emitted when |
|------|---------------|--------------|
| **CV1** | Module entirely unexecuted — likely dead in production | a file has `covered_lines == 0` and `num_statements > 0` |
| **CV2** | Function never executed during the recorded run | a `functions[...]` entry has `num_statements > 0` and `covered_lines == 0` |
| **CV3** | Module below the configured coverage floor | `percent_covered < tools.coverage.min_coverage` (only when set) |

All three are LOW-severity advisory (`custodian_policy`). A fully-unexecuted
module emits **CV1 and short-circuits** — CV2/CV3 are not also reported for it,
avoiding a flood of redundant findings.

## Producing the input

The adapter consumes the standard `coverage.py` JSON report:

```bash
# In the consuming repo's end-to-end / audit hook, after running the pipeline:
coverage run -m <your.entrypoint> ...
coverage json -o coverage.json
```

The relevant shape it reads:

```json
{
  "files": {
    "src/app/exporter.py": {
      "summary": {
        "num_statements": 40,
        "covered_lines": 0,
        "percent_covered": 0.0
      },
      "functions": {
        "build_export": {
          "summary": { "num_statements": 12, "covered_lines": 0 },
          "missing_lines": [14, 15, 16]
        }
      }
    }
  }
}
```

The `functions` block is optional — if your `coverage.json` omits it, CV2 is
silently skipped and CV1/CV3 still work.

## Configuration

Opt in under the `tools.coverage` block in `.custodian.yaml`:

```yaml
tools:
  coverage:
    enabled: true                 # default: false (opt-in)
    json_path: coverage.json      # path relative to repo root (default shown)
    min_coverage: 70              # 0-100; enables CV3. Omit to disable CV3.
    exclude_paths:                # globs matched against the file's repo-relative path
      - "src/**/_generated/**"
      - "src/**/migrations/**"
```

- **`json_path`** — relative paths are resolved against the repo root; absolute
  paths are honored as-is.
- **`min_coverage`** — when unset (`None`), **CV3 is disabled** and only the
  binary CV1/CV2 dead-code signals fire. Set it to turn on the percentage
  floor.
- **`exclude_paths`** — suppress whole files (e.g. codegen, migrations) from
  all three codes.

## Worked example

After an end-to-end run, `coverage.json` shows `src/app/exporter.py` was never
touched and `helpers.send()` never ran, with the floor set to 70:

```
src/app/exporter.py:0: module had 0/40 statements executed during the recorded run — likely dead in production   [CV1]
src/app/helpers.py:88: function 'send' never executed during the recorded run                                    [CV2]
src/app/legacy.py:0: module 18% covered (below configured min_coverage=70%)                                       [CV3]
```

How to read them:

- **CV1** — cross-check against D1 / Vulture. If static analysis *also* says
  it's dead, `triage` votes DELETE. If it's reachable but just wasn't part of
  this run's scenario, it's a coverage gap, not dead code.
- **CV2** — often an error/edge path the recorded scenario didn't hit. Add a
  test that drives it, or confirm it's genuinely unused and remove it.
- **CV3** — a threshold nudge: the module is exercised but thinly. Decide
  whether to add tests or to lower/scope the floor.

## Diagnostics

If the adapter is enabled but the input is missing or malformed, it fails
**loud but non-blocking** rather than silently producing nothing:

```
<json_path>:0: coverage.json not found at <path>; nothing to analyze   [COVERAGE_JSON_MISSING]
<json_path>:0: failed to read coverage.json: <error>                   [COVERAGE_JSON_INVALID]
```

Both are LOW severity — a misconfigured opt-in surfaces a finding you can see,
instead of an empty result you might mistake for "all clean."

## When defaults aren't right

- **Coverage that only reflects one workload.** A module exercised only by a
  batch job not present in the recorded run will show as CV1/CV2 even though
  it's live. Either include that workload in the run that produces
  `coverage.json`, or exclude the path.
- **Generated / migration code.** Codegen and DB migrations skew coverage —
  exclude them via `tools.coverage.exclude_paths`.
- **No floor wanted.** Leave `min_coverage` unset to get only the binary
  dead-code signals (CV1/CV2) without the percentage gate (CV3).

## CI gate

The adapter is opt-in and its findings are LOW / non-blocking by default. To
gate on dead-in-production code once your coverage producer is trustworthy:

```yaml
audit:
  blocking:
    - CV1   # nothing fully dead in production
    # CV2 / CV3 are commonly left advisory — edge-path functions and
    # threshold nudges carry more noise than a fully-unexecuted module.
```

## What this is not

- **Not a coverage runner.** Custodian never executes your code. You produce
  `coverage.json`; the adapter only reads it.
- **Not a static dead-code detector.** CV-class is *runtime* evidence; it
  complements but does not replace D1 / D5 / Vulture. Use them together —
  static + dynamic agreement is the strongest delete signal.
- **Not on by default.** Unlike the native detectors, the coverage adapter
  does nothing until `tools.coverage.enabled: true`.
