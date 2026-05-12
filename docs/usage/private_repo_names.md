# Boundary artifact leakage (B-class)

Public repos describe stable, reusable platform capabilities. Private
manifests bind those capabilities to specific private repos. A public
repo that names a private repo in tracked artifacts leaks the
private/public boundary.

The **B-class detectors** scan tracked files for RepoGraph-derived forbidden
names and flag any matches.

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
  require_boundary_artifact: true
  boundary_artifact_file: /path/to/boundary_disclosure_artifact.json
  # Optional. Adds to the default exclude list documented below.
  exclude_paths:
    - "examples/legacy/**"
```

or

```bash
export REPOGRAPH_BOUNDARY_ARTIFACT_FILE=/path/to/boundary_disclosure_artifact.json
```

or

```bash
export REPOGRAPH_BOUNDARY_ARTIFACT="$(cat boundary_disclosure_artifact.json)"
```

Legacy compatibility remains available through:

- `privacy.private_repo_names`
- `privacy.private_repo_names_file`
- `CUSTODIAN_PRIVATE_REPO_NAMES_FILE`
- `CUSTODIAN_PRIVATE_REPO_NAMES`

### What goes in the boundary artifact

Custodian reads `forbidden_names` from a RepoGraph boundary artifact:

```json
{
  "source_graph_id": "PrivateManifest",
  "source_ref_or_commit": "abc123",
  "forbidden_names": ["MyPrivateRepo", "myprivaterepo"],
  "allowed_aliases": ["ManagedProjectPublic"],
  "redacted_entities": ["private_impl"],
  "redaction_rules_applied": ["forbid_non_public_canonical_names"]
}
```

Match is **case-sensitive substring on file content**, line by line. The
artifact should therefore include every casing that must be treated as a leak.

### Supported artifact sources

`boundary_artifact_file` and `REPOGRAPH_BOUNDARY_ARTIFACT_FILE` accept JSON or
YAML documents with a top-level `forbidden_names` list.

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
| **B2** | Boundary artifact or private-name source is required but missing | MEDIUM | Returns 0 findings unless `require_boundary_artifact: true` or `require_private_repo_name_source: true` |

B1 reports one finding per matching line, with samples showing the
first ~8 violations as `path:lineno: contains 'NAME'`. The total count
reflects every match across the repo so consumers can drive a hard
gate when needed.

## CI gate pattern

```yaml
# .custodian/config.yaml
privacy:
  require_boundary_artifact: true

audit:
  blocking:
    - B1   # block any merge that introduces a private-repo name
    - B2   # block any merge if the private-name source is missing
```

## What the detector does NOT do

- It does not resolve git history or detect names in past commits —
  scrub history with `git filter-repo` separately if needed.
- It does not match aliases or abbreviations heuristically. List every
  string explicitly.
- It does not look inside binary blobs, including images that may
  contain text via OCR. Manage binary leaks separately.
- It does not generate the boundary artifact itself. `PrivateManifest` does
  that from RepoGraph identity metadata.
