# Private repo name leakage (B-class)

Public repos describe stable, reusable platform capabilities. Private
manifests bind those capabilities to specific private repos. A public
repo that names a private repo in tracked artifacts leaks the
private/public boundary.

The **B-class detectors** scan tracked files for configured
private-repo names and flag any matches.

## When to enable it

Add a `privacy:` block to your `.custodian/config.yaml` whenever the
repo:

- ships under a public visibility (open source, vendor distribution,
  external contractors), but
- the platform it belongs to includes private repos that operators of
  the public repo should not learn about.

## Configuration

```yaml
privacy:
  private_repo_names:
    - PrivateRepoName
    - privaterepo_name
  # Optional. Adds to the default exclude list documented below.
  exclude_paths:
    - "examples/legacy/**"
```

### What goes in `private_repo_names`

The literal string an operator would see in tracked text. Match is
**case-sensitive substring on file content**, line by line. List every
casing that appears in your codebase explicitly:

```yaml
private_repo_names:
  - MyPrivateRepo       # matches docstrings, README mentions
  - myprivaterepo       # matches package imports, YAML keys
  - MYPRIVATEREPO       # matches uppercase enum values
```

The detector does not normalise casing because the surface that
leaks is the literal string, not a canonical identifier.

### Default excludes

These paths are **always** excluded — they are operator-private or
historical and may legitimately mention names that no longer should
appear in current public state:

| Path pattern                    | Why excluded                                                    |
|---------------------------------|-----------------------------------------------------------------|
| `.console/**`                   | Operator workspace; historical narration may name past bindings |
| `config/managed_repos/local/**` | Gitignored overlay where real bindings live                     |
| `docs/history/**`               | Historical docs that recount past events                        |
| `tools/audit/report/**`         | Audit reports that may have captured past leaks                 |

Add to the list in `privacy.exclude_paths` when your repo has its own
operator-private surfaces (for example, `examples/legacy/**` after a
rename migration).

### Binary-file skip

Common binary suffixes (`.png`, `.jpg`, `.zip`, `.pdf`, `.so`, etc.)
are skipped automatically — the detector only scans text content.

## Detector reference

| Code | Description | Severity | Behavior on empty config |
|------|-------------|----------|--------------------------|
| **B1** | Tracked file contains a private-repo name | MEDIUM | Returns 0 findings (silent) |

B1 reports one finding per matching line, with samples showing the
first ~8 violations as `path:lineno: contains 'NAME'`. The total count
reflects every match across the repo so consumers can drive a hard
gate when needed.

## CI gate pattern

```yaml
# .custodian/config.yaml
privacy:
  private_repo_names:
    - MyPrivateRepo
    - myprivaterepo

audit:
  blocking:
    - B1   # block any merge that introduces a private-repo name
```

## What the detector does NOT do

- It does not resolve git history or detect names in past commits —
  scrub history with `git filter-repo` separately if needed.
- It does not match aliases or abbreviations heuristically. List every
  string explicitly.
- It does not look inside binary blobs, including images that may
  contain text via OCR. Manage binary leaks separately.
- It does not enforce the migration pattern (private bindings under
  `config/managed_repos/local/`, or whatever overlay convention your
  consumer uses) — it just confirms public surfaces stay clean.
