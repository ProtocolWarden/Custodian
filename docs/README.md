# Custodian Documentation

Index for the `docs/` tree. The README at the repo root covers detector classes,
quick start, and the consumer config shape; this directory holds longer-form
design notes and usage guides.

## Design

- [design/detector_disposition_matrix.md](design/detector_disposition_matrix.md) —
  Per-detector decisions about whether to keep, deprecate, or retire each
  built-in detector. Authoritative source for "is this detector active?" and
  the rationale behind tool-first deprecation.

## Usage

- [usage/forbidden_import_prefix.md](usage/forbidden_import_prefix.md) —
  How to use `forbidden_import_prefix` in `.custodian/config.yaml` to ban an
  import surface across a glob. Pairs with the A1 architecture invariant
  detector.
- [usage/triage_signals.md](usage/triage_signals.md) —
  How the triage layer joins per-detector findings into per-file action
  verdicts (DELETE / IMPLEMENT / WIRE / REDESIGN / CLEANUP). Read this if
  you're configuring `audit.triage` or consuming `custodian-triage` output.
- [usage/doc_conventions.md](usage/doc_conventions.md) —
  Repo-wide markdown conventions enforced by the DC class (front matter,
  cross-doc references, ADR naming, README sections). Covers DC1–DC5 and
  DC10; DC6–DC9 are registered but not yet written up.
- [usage/incomplete_integration.md](usage/incomplete_integration.md) —
  How D12 flags a public symbol that tests exercise but production never
  calls — the "built it, tested it, never wired it" gap — and how to adopt
  it on a repo with an existing backlog via `audit.d12_baseline`.
- [usage/prompt_injection_signatures.md](usage/prompt_injection_signatures.md) —
  How INJ1 scans tracked text for invisible and bidirectional control
  characters, why it is opt-in, and why findings report a codepoint but
  never the surrounding text.
- [usage/private_repo_names.md](usage/private_repo_names.md) —
  How the B1 boundary detector enforces the public/private repo
  boundary by flagging private-repo names that leak into tracked files.
- [usage/platform_manifest_visibility.md](usage/platform_manifest_visibility.md) —
  How PMV detectors validate public PlatformManifest projections against
  forbidden fields, private terms, internal paths, URLs, and unsafe edges.
- [usage/test_presence.md](usage/test_presence.md) —
  How the T6/T7/T8 test-presence trio enforce that source modules are imported
  by a test, have a parallel test file, and that test files reference src.
- [usage/stale_github_urls.md](usage/stale_github_urls.md) —
  How the X3 detector flags stale GitHub URLs in docs against the canonical
  org/repo names derived from `platform_manifest.yaml`.
- [usage/coverage_adapter.md](usage/coverage_adapter.md) —
  How the CV1/CV2/CV3 coverage detectors ingest a `coverage.json` to flag
  unexecuted modules/functions and below-threshold coverage.

## Operations

- [semantic-federation.md](semantic-federation.md) — How to run the
  cross-repo semantic federation gate locally and in CI.
