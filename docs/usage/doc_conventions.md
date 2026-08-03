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
| **DC10** | A doc claims a feature is integrated **and** the same doc still lists that integration as deferred | `.console/*.md`, `docs/**/*.md` | Always runs — but **opt-in**, see below |

DC6–DC9 are registered but not yet documented here.

## DC10 — claims-integrated-while-deferring

DC10 is different enough from DC1–DC5 to be worth its own section: it is
**off by default**, it is configured under `audit:` rather than
`doc_conventions:`, and it fires on a *contradiction* rather than a missing
convention.

### What it catches

The planner-level half of OperationsCenter#313. The backlog asserted
"✅ IMPLEMENTATION COMPLETE & VERIFIED / end-to-end" while, further down the
same file, a "Next Steps — Stage 5 (Ready to Start)" section listed the
integration as still to do. Both statements were written in good faith; only
the first one got read.

D12 catches this in code (a symbol tested but never called). DC10 catches it in
prose — the same failure, one layer earlier.

### Why it rarely false-positives

A finding requires **both** halves to appear in the same file:

- a *strong* completion claim — `end-to-end integration` / `fully integrated` /
  `fully wired` / `integration complete` / `wired end-to-end`. A bare "done" or
  "complete" is not enough, by design.
- a deferral marker — `integration deferred` / `integration to follow` /
  `integration pending` / `tracked separately` / `not yet wired` /
  `not yet integrated` / `defer the integration` / `wire it up` /
  `update X to call Y` / `stage N … wire|integrat`.

Matching is case-insensitive. "Stage 1 complete, Stage 2 next" does **not**
fire — staged work is legitimate, and DC10 deliberately avoids the broad
"complete + next steps" pattern that would flag every honest roadmap.

### Enabling it

DC10 ships `deprecated=True`. As with D12 and INJ1, that flag is being reused as
the off-by-default lever rather than signalling tool replacement — a new
heuristic detector must not red-wall consumers that audit against
`Custodian@main`.

```bash
custodian audit --only DC10 --include-deprecated
```

### Configuring it

DC10's keys live under `audit:`, **not** under the `doc_conventions:` block that
DC1–DC5 use. This is an inconsistency in the current schema; write it as shown:

```yaml
# .custodian/config.yaml
audit:
  # Where DC10 looks. Defaults to the .console truth files plus docs/.
  dc10_scan_globs:
    - ".console/*.md"
    - "docs/**/*.md"
    - "planning/**/*.md"

  # Accepted pre-existing contradictions, by repo-relative path. A ratchet —
  # it should only shrink.
  dc10_baseline:
    - "docs/design/legacy-rollout.md"

  exclude_paths:
    DC10:
      - "docs/archive/**"
```

Unlike `d12_baseline`, which lists symbol names, `dc10_baseline` lists
**repo-relative file paths** and matches them exactly.

### Acting on a finding

```
.console/backlog.md:12: claims integrated ('end-to-end integration') but defers the integration ('Stage 5 — wire the caller')
```

The fix is almost never to soften the wording. Either the integration is done —
in which case delete the stale deferred section — or it is not, in which case
the completion claim is wrong and should say what actually shipped. DC10 is
pointing at a document that will mislead the next reader either way.

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
