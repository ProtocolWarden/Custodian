# Doc conventions (DC-class)

R-class enforces README structural shape (presence, H1, "What X is",
intro paragraph, `docs/` index). K-class enforces doc-code consistency
(phantom symbols, value drift, param drift). **DC-class** fills the gap
between them — repo-wide markdown conventions for design specs,
ADRs, and cross-doc references.

All DC detectors are LOW severity. They report findings but never
block; the count drops over time as operators fix or formally exempt
offenders.

## Detectors

| Code | What it checks | Default location | Behavior when location absent |
|------|----------------|------------------|-------------------------------|
| **DC1** | Design specs start with a YAML front matter block declaring `status:` | `docs/design/` | Silent (skipped) |
| **DC2** | Cross-doc references of the form `` `docs/X.md` `` resolve to a file that exists | scans `README.md` + `docs/**.md` | Always runs |
| **DC3** | ADRs follow `NNNN-kebab-case.md` (zero-padded ordinal + kebab-case title) | `docs/architecture/adr/` | Silent (skipped) |
| **DC4** | README has `## Quick start` (or alternates) AND `## Architecture` (or alternates) at H2 level | repo root `README.md` | Silent when README absent — R1 covers that |
| **DC5** | Backtick-quoted symbols inside `**Files:**` / `Implementation:` lines use a module-qualified path (containing `.`, `:`, or `/`) | `docs/design/`, `docs/architecture/` | Silent when neither dir exists |

## Configuration

All defaults work without config. Override via a top-level
`doc_conventions:` block in `.custodian/config.yaml`:

```yaml
doc_conventions:
  # DC1 — where design specs live
  design_dir: docs/design
  # DC3 — where ADRs live
  adr_dir: docs/architecture/adr
  # DC2 + DC5 — markdown scan roots
  doc_scan_dirs:
    - docs
  # DC2 + DC5 — paths (fnmatch globs) excluded from cross-ref + symbol checks
  exclude_path_patterns:
    - "*/archive/*"
    - "*/history/*"
  # DC4 — required README H2 patterns (Python regex, OR each label
  # by alternation). When you override this list, samples report
  # "section #N" instead of the friendly default labels.
  required_readme_headings:
    - "^##\\s+(?:Quick\\s+start|Quickstart|Getting\\s+started)\\b"
    - "^##\\s+(?:Architecture|Overview|How\\s+it\\s+works)\\b"
```

## When defaults aren't right

- **DC1** assumes `docs/design/` is your design-spec dir. Move via
  `design_dir`. Useful if your repo uses `specs/` or `design-docs/`.
- **DC3** assumes `docs/architecture/adr/`. Move via `adr_dir`. Some
  repos use `docs/adr/` or `decisions/` — point the detector at it.
- **DC4** is opinionated about README sections. If your repos
  legitimately don't ship a Quick start (e.g., a library that's just
  imported), override `required_readme_headings` with the pattern
  set you actually expect, or set it to `[]` to disable DC4 entirely.
- **DC2 / DC5** widen scope by adding more dirs to `doc_scan_dirs`.
  Both detectors honor `exclude_path_patterns` so historical or
  archived narration doesn't trip the rules.

## CI gate

DC findings are LOW severity, so they don't block by default. To
gate merges on a clean DC count:

```yaml
# .custodian/config.yaml
audit:
  blocking:
    - DC1   # design specs must declare status
    - DC2   # no dead doc refs
    - DC3   # ADRs follow naming
    # DC4 / DC5 are commonly left advisory
```

## What this is not

- **Not** a markdown linter. Use `markdownlint` for prose style,
  trailing whitespace, list ordering, etc.
- **Not** a schema validator for front matter contents — DC1 only
  checks that `status:` exists, not that its value is a member of
  some enum. Add a custom plugin detector for stricter front matter.
- **Not** a link checker for HTTP URLs. DC2 only resolves
  filesystem-relative `` `docs/X.md` `` references inside backticks.
