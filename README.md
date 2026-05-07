# Custodian

Custodian is a pip-installable cross-repo audit and maintenance toolkit for Python repos. It centralizes reusable detector logic and maintenance helpers so teams can stop re-implementing the same operational checks in each consumer repository.

## Why it exists

Large multi-repo organizations need consistent health checks and maintenance routines, but each repo has local conventions. Custodian provides shared infrastructure (detector execution, schema-stable result output, plugin loading) while letting each consumer supply repo-specific plugins and config.

## Quick start

```bash
pip install custodian
custodian-doctor
custodian-audit
```

For local development against this repo:

```bash
pip install -e .[dev]
```

## Detector model

Detectors are grouped by namespace. Each detector has an ID, a severity (LOW/MEDIUM/HIGH), and a set of analysis passes it requires (none, `ast_forest`, `call_graph`).

| Class | Active | Focus |
|-------|--------|-------|
| C | 16 | File-local code health: style, safety, security patterns |
| D | 4 | Dead code: unreachable paths, unused definitions, no-op constructs |
| F | 1 | Dead fields: unused dataclass / Pydantic fields and constants |
| U | 4 | Unimplemented stubs: raise NIE / ellipsis / docstring-only bodies |
| K | 3 | Documentation consistency: phantom symbols, value drift, param drift |
| S | 4 | Structure: layer violations, circular imports, test-in-prod imports, conftest guard |
| A | 2 | Architecture invariants: field counts, directory shape (declarative YAML) |
| H | 1 | Hexagonal layer ordering violations |
| T | 8 | Test shape: coverage, assertions, unconditional skips, parametrize hygiene, etc. |
| G | 1 | Ghost work: comment references to removed types |
| N | 1 | Naming: exception class naming convention |
| P | 1 | Partial implementations: hollow return bodies |

A further 21 detectors are kept as **deprecated** — third-party tools (ruff, vulture, ty) cover the same cases natively, so these no longer participate in audits but stay importable for backward compatibility. See `docs/design/detector_disposition_matrix.md`.

Consumer repos can add plugin detectors by supplying Python modules via the `plugins` key in `.custodian.yaml`. See `tests/fixtures/sample_consumer/` for a concrete example.

## Consumer configuration (`.custodian.yaml`)

Each consumer repo declares:

- `repo_key`: stable identifier
- `src_root` and `tests_root`: relative paths for scanning
- `audit` settings (for example stale handler names and common words)
- `plugins`: module import targets used by Custodian
- `maintenance` thresholds

See `tests/fixtures/sample_consumer/.custodian.yaml` for a concrete example.

## Versioning and schema stability

Custodian follows semantic versioning from day 1. Audit output is explicitly versioned using `schema_version` in `AuditResult`; v0.1 emits `schema_version = 1`.

## License

GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later) — see [LICENSE](LICENSE).
