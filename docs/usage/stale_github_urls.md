# X3 — stale GitHub URLs in docs

When a platform repo is renamed, its old name lingers in two places: bare
string references in prose (caught by the cross-repo **X1** label-drift check)
and **GitHub URLs** in docs that still point at the legacy slug. **X3** is the
URL-level companion — it flags markdown files that link to
`github.com/<owner>/<LegacyName>` when the platform manifest says the canonical
URL uses `<CanonicalName>`.

LOW severity, advisory (`custodian_policy`), module `cross_repo.py`.

> **Namespace note.** `cross_repo.py` reuses the `X` prefix for a cross-repo
> *drift* family (X1 label reference, X2 undeclared cross-repo import, X3 stale
> URL). These are unrelated to `complexity.py`'s `X1`/`X2` (cyclomatic
> complexity / too-many-params) and never collide at runtime — they live under
> different detector builders.

## How it works

X3 reads the platform manifest (`platform_manifest.yaml`) and, for each repo
entry, pairs the canonical `github_url` with the repo's known legacy labels to
derive a **stale → canonical** URL map. For example, if the manifest says:

```yaml
repos:
  - canonical: OperationsCenter
    legacy: [ControlPlane, OperationsCenterPublic]
    github_url: https://github.com/ProtocolWarden/OperationsCenter
```

then X3 looks for `github.com/ProtocolWarden/ControlPlane` and
`github.com/ProtocolWarden/OperationsCenterPublic` in any `.md` file and flags
each occurrence:

```
docs/integration.md:42: stale GitHub URL `github.com/ProtocolWarden/ControlPlane` — PlatformManifest canonical is `https://github.com/ProtocolWarden/OperationsCenter`
```

Matching is scheme-agnostic (`https://`, `http://`, or bare `github.com/...`
all match) and findings are deduplicated by `(path, line, fragment)` so a line
with two stale URLs reports both but a re-scan reports neither twice.

## Configuration

Works with zero config when a `platform_manifest.yaml` is discoverable. Tune
under `audit:` in `.custodian/config.yaml`:

```yaml
audit:
  # Paths (glob, repo-relative) excluded from the X3 scan
  exclude_paths:
    X3:
      - "docs/history/**"       # archived narration — old URLs are expected
      - "CHANGELOG.md"          # historical entries reference old names
```

X3 also honors the shared cross-repo manifest-location and skip-root settings
used by X1/X2 (it calls the same `_load_manifest_info` / `_extra_skip_roots`
helpers), so pointing those at a non-default manifest path or excluding extra
roots applies to X3 automatically.

## Worked example

A how-to doc written before a repo rename:

```markdown
<!-- docs/onboarding.md -->
Clone the orchestrator:

    git clone https://github.com/ProtocolWarden/ControlPlane
```

After `ControlPlane` was renamed to `OperationsCenter` in the manifest, X3
reports:

```
docs/onboarding.md:5: stale GitHub URL `github.com/ProtocolWarden/ControlPlane` — PlatformManifest canonical is `https://github.com/ProtocolWarden/OperationsCenter`
```

Fix: update the URL to the canonical slug. If the line is deliberately
historical (a changelog entry recording the old name), add the file to
`audit.exclude_paths.X3`.

## When defaults aren't right

- **Historical / archived docs.** Changelogs, ADRs recording a rename, and
  `docs/history/**` legitimately contain the old URL. Exclude them rather than
  rewriting history.
- **No manifest, no findings.** X3 is a no-op when no
  `platform_manifest.yaml` is discoverable or when no repo entry has both a
  `github_url` and a legacy label — there's nothing to compute a stale URL
  from. This is intentional: a standalone repo with no platform context can't
  have cross-repo URL drift.

## CI gate

LOW / non-blocking by default. To fail merges on a stale link:

```yaml
audit:
  blocking:
    - X3
```

## What this is not

- **Not a link checker.** X3 does not verify the URL resolves (200 OK) — it
  only checks the *slug* against the manifest's canonical name. Use a real
  link checker for dead-link detection.
- **Not a string-name check.** Bare prose mentions of a legacy repo name
  (without a `github.com/` URL) are X1's job, not X3's.
- **Not limited to one owner.** The stale→canonical map is derived per
  manifest entry, so any owner/org present in a `github_url` is covered.
