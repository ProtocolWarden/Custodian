# `forbidden_import_prefix` — declarative import-policy rule

Use this when you want to ban an entire import namespace from a set of files.
The rule covers **both** import forms in one declaration:

```python
import foo.bar         # caught
from foo.bar import x  # caught
```

It also catches every submodule under the prefix:

```python
import foo.bar.baz             # caught (sub-module)
from foo.bar.baz.qux import y  # caught (sub-module)
```

## Where to put it

Inside `architecture.layers` in `.custodian/config.yaml` (the preferred layout; legacy `.custodian.yaml` single-file form is also still loaded):

```yaml
architecture:
  layers:
    - name: "no managed-repo imports in OC src"
      glob: "src/operations_center/**/*.py"
      forbidden_import_prefix: "example_managed_repo"

    - name: "no tools.audit in runtime code"
      glob: "src/**/*.py"
      forbidden_import_prefix: "tools.audit"
```

Each layer entry is an independent rule — repeat the pattern for each
forbidden prefix.

## Why use this instead of a custom Python detector

Custom AST walkers for import-direction policy creep into projects fast.
Once you have one, every new "ban X from Y" rule means writing more
detector code. The boundary spec (Custodian Boundary Refinement) places
all import-direction policy in declarative config:

| Rule type                | Implementation                         |
|--------------------------|----------------------------------------|
| Import policy            | `forbidden_import_prefix` (this rule)  |
| Layer direction          | `architecture.layers`                  |
| Call-pattern checks      | Semgrep                                |
| Repo/file-shape          | Custom Python policy (last resort)     |

If you find yourself writing `for node in ast.walk(tree): if isinstance(node, ast.ImportFrom)…`,
stop and use this instead.

## Worked examples

The patterns below are the typical shapes the rule expresses. Real
bindings (which prefix is banned where) live in each consumer's own
`.custodian/config.yaml`, not in this public doc.

- **Orchestration repo / managed-repo isolation** — bans an external
  managed-repo's package prefix from the orchestration repo's runtime
  `src/**`. Used to keep an audit-target's vocabulary out of the
  orchestrator's call paths.
- **Managed repo / canonical-adapter rule** — bans direct `SingletonDB`
  import everywhere except the canonical adapter module, forcing all
  callers through one chokepoint.
- **Managed repo / runtime-vs-tooling split** — bans `tools.audit` and
  `tools.reports` from runtime `src/**` so audit/reporting helpers
  can't leak into production paths.

## Tests

`tests/test_structure_detectors.py` covers:

- `forbidden_import_prefix` direct import (`import foo.bar`)
- `forbidden_import_prefix` from-import (`from foo.bar import x`)
- `forbidden_import_prefix` sub-module match (`from foo.bar.baz import y`)
- Negative cases (imports that don't match the prefix)
