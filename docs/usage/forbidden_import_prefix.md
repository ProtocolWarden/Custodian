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

Inside `architecture.layers` in `.custodian.yaml` (or `.custodian/config.yaml`):

```yaml
architecture:
  layers:
    - name: "no managed-repo imports in OC src"
      glob: "src/operations_center/**/*.py"
      forbidden_import_prefix: "videofoundry"

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

## Real consumers

- **OperationsCenter / AI1** — bans `videofoundry`, `tools.audit`, `managed_repo` from `src/operations_center/**`. See `OperationsCenter/.custodian/config.yaml`.
- **VideoFoundry / VF2** — bans direct `SingletonMongoDB` import outside the canonical Mongo adapter. See `VideoFoundry/.custodian/config.yaml`.
- **VideoFoundry / VF4** — bans `tools.audit` and `tools.reports` from runtime `src/**`. See `VideoFoundry/.custodian/config.yaml`.

## Tests

`tests/test_structure_detectors.py` covers:

- `forbidden_import_prefix` direct import (`import foo.bar`)
- `forbidden_import_prefix` from-import (`from foo.bar import x`)
- `forbidden_import_prefix` sub-module match (`from foo.bar.baz import y`)
- Negative cases (imports that don't match the prefix)
