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
  Repo-wide markdown conventions enforced by DC1–DC8 (front matter,
  cross-doc references, ADR naming, README sections, section ordering).
- [usage/private_repo_names.md](usage/private_repo_names.md) —
  How the B1 boundary detector enforces the public/private repo
  boundary by flagging private-repo names that leak into tracked files.
