# Contributing to Custodian

Custodian is the cross-repo audit and maintenance toolkit. It provides a reusable detector framework, generic code-health audits, and operational maintenance helpers that consumer repos install as a dev-dependency and extend with their own per-repo plugins.

## Before You Start

- Check open issues to avoid duplicate work
- For significant changes, open an issue first to discuss the approach
- All contributions must pass the test suite and linter before merging

## Development Setup

```bash
git clone https://github.com/ProtocolWarden/Custodian.git
cd Custodian
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

Requires Python 3.11+.

## Running Tests

```bash
.venv/bin/python -m pytest tests/ -v
```

## Running the Linter

```bash
ruff check src/
```

## Project Structure

```
src/custodian/
  audit_kit/            # Detector framework, generic detectors, JSON result schema
    detector.py         # Detector + DetectorResult + AuditContext dataclasses
    result.py           # AuditResult — versioned via SCHEMA_VERSION
    code_health.py      # generic C1-C8 detectors (consumer-configurable)
    doc_conventions.py  # generic C9 detector (status fields, headings)
    invariants.py       # import-boundary checker
  maintenance_kit/      # cross-cutting maintenance helpers
    stale_running.py    # reconcile stale Running issues
    stale_state.py      # cleanup expired per-task state files
    stale_pr.py         # close PRs idle past a configured horizon
  plugins/              # consumer plugin loading + protocols
    loader.py           # reads .custodian/config.yaml, imports declared modules
    protocols.py        # LogScanner, StateScanner protocol classes
  cli/                  # entry-point commands
    audit.py            # `custodian-audit`
    doctor.py           # `custodian-doctor`
    runner.py           # shared orchestration
```

## Architectural Constraints

Custodian is a **library + CLI**. It holds reusable patterns. Per-repo data flows belong in the consumer repo. Contributions must not:

- Hardcode any consumer-specific path, log format, or state-file shape into the library
- Add adapters for Plane, GitHub, or other external services (those live near their primary consumer)
- Build aggregation infrastructure (the JSON output is aggregator-friendly; the aggregator itself is out of scope for v0.x)
- Break the `AuditResult.schema_version` contract without bumping the major version

The plugin model is config-declared: consumers ship a `.custodian/config.yaml` listing the modules and detectors Custodian should load.

## Pull Requests

- Keep PRs focused — one concern per PR
- New detectors must include tests against fixture directories in `tests/fixtures/`
- Schema-shape changes require a `schema_version` bump and a migration note
- Update `README.md` if the change affects the consumer-facing CLI or `.custodian/config.yaml` keys

## Commit Style

| Prefix | Use for |
|--------|---------|
| `feat:` | new user-facing feature |
| `fix:` | bug fix |
| `refactor:` | internal restructure, no behavior change |
| `docs:` | documentation only |
| `test:` | test additions or fixes |
| `chore:` | tooling, CI, dependency updates |

## Versioning

Custodian uses semver. Detector result JSON is versioned via the `schema_version` field in `audit_kit/result.py`. Breaking changes to the schema or the public CLI surface require a major-version bump.

## Code of Conduct

This project follows the [Contributor Covenant v2.1](CODE_OF_CONDUCT.md). By participating you agree to uphold its standards.
