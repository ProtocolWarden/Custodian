# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
"""S-class detectors — structural / architecture invariants.

These detectors require the ``import_graph`` analysis pass.  They answer
questions about relationships *between* modules rather than patterns within
a single file.

Note: the A2 (directory structure) detector lives in ``directory.py`` and is
registered by ``build_directory_detectors()``.

Detectors
─────────
A1  Architecture invariants — declarative YAML rules enforcing structural
    constraints per file/glob.  Rules are expressed in ``.custodian.yaml``
    under ``architecture.invariants``.  Each rule may enforce one of:
    max_lines, max_classes, max_functions, forbidden_import,
    forbidden_import_prefix, public_api_only, or class_field_count.
    If no invariants are declared the detector silently reports 0 findings.

S1  Layer boundary violations — files in a declared layer import from a
    layer they are forbidden to depend on.  Rules are expressed in
    ``.custodian.yaml`` under ``architecture.layers``.  If no rules are
    declared the detector silently reports 0 findings.

S2  Mutual imports — module A imports module B and module B imports module A
    (runtime imports only; TYPE_CHECKING-guarded imports are excluded).
    Mutual imports almost always indicate a design problem: the two modules
    should be merged, or one should expose an interface the other depends on.

S3  Test-only imports in production code — a ``src/`` file imports from a
    ``tests.*`` or ``test_*`` module.  Test utilities should not leak into
    production code; shared fixtures belong in a separate ``conftest.py``
    or helper package inside ``src/``.

S4  Missing venv guard in tests/conftest.py — the top-level conftest must
    contain a ``sys.prefix`` / ``_EXPECTED_VENV`` check so that tests cannot
    silently run against the wrong Python environment.  Absent guard means CI
    or a developer can run the suite with a foreign venv and get misleading
    green results from the wrong package versions.

H1  Hexagonal architecture layer ordering — layers declared under
    ``architecture.hex`` must only import from layers earlier (lower index)
    in the list.  The ordering is the canonical dependency direction:
    domain → application → adapters/ports → infrastructure.  More opinionated
    and concise than S1's explicit ``may_not_import`` lists.

Config example for S1::

    architecture:
      layers:
        - name: adapters
          glob: "src/myapp/adapters/**"
          may_not_import:
            - "src/myapp/entrypoints/**"
        - name: domain
          glob: "src/myapp/domain/**"
          may_not_import:
            - "src/myapp/adapters/**"
            - "src/myapp/entrypoints/**"

Config example for H1 (hexagonal architecture)::

    architecture:
      hex:
        # Listed from innermost to outermost. Each layer may only import
        # from layers earlier in this list (lower index).
        - name: domain
          glob: "src/myapp/domain/**"
        - name: application
          glob: "src/myapp/application/**"
        - name: adapters
          glob: "src/myapp/adapters/**"
        - name: infrastructure
          glob: "src/myapp/infrastructure/**"

Config example for A1 class_field_count::

    architecture:
      invariants:
        - name: "WorkflowContext size guard"
          glob: "src/**/*.py"
          class_field_count:
            class_name: "WorkflowContext"
            max_fields: 20

Config example for A1 public_api_only — enforce that imports of an
external package only go through its declared public surfaces. Use
this when consuming an extracted library to prevent deep imports
that bypass the public API contract::

    architecture:
      invariants:
        - name: "CoreRunner: public API only"
          glob: "src/operations_center/**"
          public_api_only:
            package: "core_runner"
            allowed_paths:
              - "core_runner"
              - "core_runner.runners"
              - "core_runner.contracts"

Any import of ``core_runner.*`` whose imported module path is
not in ``allowed_paths`` (exact match) is flagged. This enforces
boundary discipline that ``forbidden_import_prefix`` can't express
(it's all-or-nothing).

Globs are matched against file paths relative to repo_root.
"""
from __future__ import annotations

import ast
from pathlib import Path

from custodian.audit_kit.detector import (
    LOW,
    MEDIUM,
    AuditContext,
    Detector,
    DetectorResult,
)
from custodian.audit_kit.glob_match import glob_match

_MAX_SAMPLES = 8
_NEEDS = frozenset({"import_graph"})
_NEEDS_AST = frozenset({"ast_forest"})


def build_structure_detectors() -> list[Detector]:
    return [
        Detector("A1", "architecture invariant violation (max_lines/max_classes/forbidden_import)", "open",
                 detect_a1, MEDIUM, _NEEDS_AST),
        Detector("S1", "architecture layer boundary violations", "open", detect_s1,
                 MEDIUM, _NEEDS),
        Detector("S2", "mutual imports (direct circular dependencies)", "open", detect_s2,
                 LOW, _NEEDS),
        Detector("S3", "test-only import in production code", "open", detect_s3,
                 MEDIUM, _NEEDS_AST),
        Detector("S4", "tests/conftest.py missing venv guard", "open", detect_s4,
                 MEDIUM, frozenset()),
        Detector("H1", "hexagonal architecture layer ordering violation", "open", detect_h1,
                 MEDIUM, _NEEDS),
    ]


# ── helpers ──────────────────────────────────────────────────────────────────

def _glob_match(rel_path: Path, glob: str) -> bool:
    """Match a repo-relative path against a glob pattern.

    Uses fnmatch so that ``**`` matches any number of path components
    (including those with ``/`` separators), which pathlib.match() does not
    handle correctly for nested directories in Python 3.12.
    """
    return glob_match(rel_path.as_posix(), glob)


def _any_glob(rel_path: Path, globs: list[str]) -> bool:
    return any(_glob_match(rel_path, g) for g in globs)


def _parse_layer_rules(config: dict) -> list[dict]:
    """Return the list of layer rule dicts from config, or []."""
    arch = config.get("architecture") or {}
    return list(arch.get("layers") or [])


def _parse_invariants(config: dict) -> list[dict]:
    """Return the list of architecture invariant dicts from config, or []."""
    arch = config.get("architecture") or {}
    return list(arch.get("invariants") or [])


# ── A1: architecture invariants ──────────────────────────────────────────────

def detect_a1(context: AuditContext) -> DetectorResult:
    """Flag files that violate declared architecture invariants.

    Rules are declared in .custodian.yaml under architecture.invariants.
    Each rule applies to files matching its glob and checks one constraint:
    max_lines, max_classes, max_functions, or forbidden_import.
    If no invariants are declared, silently returns 0 findings.
    """
    if context.graph is None or context.graph.ast_forest is None:
        return DetectorResult(count=0, samples=[])

    invariants = _parse_invariants(context.config)
    if not invariants:
        return DetectorResult(count=0, samples=[])

    audit_cfg: dict = context.config.get("audit") or {}
    a1_excludes: list[str] = list((audit_cfg.get("exclude_paths") or {}).get("A1") or [])

    samples: list[str] = []
    count = 0

    for path, tree, src in context.graph.ast_forest.items():
        rel = path.relative_to(context.repo_root)
        rel_posix = rel.as_posix()

        if a1_excludes and any(glob_match(rel_posix, excl) for excl in a1_excludes):
            continue

        for rule in invariants:
            glob = rule.get("glob") or ""
            if not glob or not _glob_match(rel, glob):
                continue
            name = rule.get("name") or glob

            # max_lines
            if "max_lines" in rule:
                limit = int(rule["max_lines"])
                actual = len(src.splitlines())
                if actual > limit:
                    count += 1
                    if len(samples) < _MAX_SAMPLES:
                        samples.append(
                            f"{rel_posix}:{actual} lines — exceeds {name!r} limit of {limit}"
                        )

            # max_classes
            if "max_classes" in rule:
                limit = int(rule["max_classes"])
                actual = sum(1 for n in ast.walk(tree) if isinstance(n, ast.ClassDef))
                if actual > limit:
                    count += 1
                    if len(samples) < _MAX_SAMPLES:
                        samples.append(
                            f"{rel_posix}:{actual} classes — exceeds {name!r} limit of {limit}"
                        )

            # max_functions (module-level only)
            if "max_functions" in rule:
                limit = int(rule["max_functions"])
                actual = sum(
                    1 for s in tree.body
                    if isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef))
                )
                if actual > limit:
                    count += 1
                    if len(samples) < _MAX_SAMPLES:
                        samples.append(
                            f"{rel_posix}:{actual} functions — exceeds {name!r} limit of {limit}"
                        )

            # forbidden_import — glob match against dotted module path (dots → slashes)
            if "forbidden_import" in rule:
                pattern = rule["forbidden_import"]
                path_pattern = pattern.replace(".", "/")
                for node in ast.walk(tree):
                    mod = None
                    lineno = 0
                    if isinstance(node, ast.Import):
                        for alias in node.names:
                            mod_as_path = alias.name.replace(".", "/")
                            if _glob_match(Path(mod_as_path), path_pattern):
                                mod = alias.name
                                lineno = node.lineno
                                break
                    elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
                        mod_as_path = node.module.replace(".", "/")
                        if _glob_match(Path(mod_as_path), path_pattern):
                            mod = node.module
                            lineno = node.lineno
                    if mod:
                        count += 1
                        if len(samples) < _MAX_SAMPLES:
                            samples.append(
                                f"{rel_posix}:{lineno}: imports {mod!r} — forbidden by {name!r}"
                            )
                        break  # one violation per rule per file is enough

            # forbidden_import_prefix — prefix match (exact or sub-module).
            # Use this instead of forbidden_import when you want to catch both
            # `import foo` and `from foo.bar import baz` with a single rule.
            if "forbidden_import_prefix" in rule:
                prefix = rule["forbidden_import_prefix"]
                prefix_path = prefix.replace(".", "/")
                for node in ast.walk(tree):
                    mod = None
                    lineno = 0
                    if isinstance(node, ast.Import):
                        for alias in node.names:
                            mp = alias.name.replace(".", "/")
                            if mp == prefix_path or mp.startswith(prefix_path + "/"):
                                mod = alias.name
                                lineno = node.lineno
                                break
                    elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
                        # node.level > 0 means a relative import (from .foo import) — skip
                        mp = node.module.replace(".", "/")
                        if mp == prefix_path or mp.startswith(prefix_path + "/"):
                            mod = node.module
                            lineno = node.lineno
                    if mod:
                        count += 1
                        if len(samples) < _MAX_SAMPLES:
                            samples.append(
                                f"{rel_posix}:{lineno}: imports {mod!r} — forbidden prefix {prefix!r}"
                            )
                        break  # one violation per rule per file is enough

            # class_field_count — named class must not exceed max declared fields.
            # Counts ast.AnnAssign entries in the class body (dataclass / NamedTuple
            # style). Useful for god-object detection (e.g. WorkflowContext).
            if "class_field_count" in rule:
                cfg = rule["class_field_count"]
                class_name: str = cfg.get("class_name", "")
                max_fields: int = int(cfg.get("max_fields", 20))
                if class_name:
                    for node in ast.walk(tree):
                        if not isinstance(node, ast.ClassDef):
                            continue
                        if node.name != class_name:
                            continue
                        field_count = sum(
                            1 for item in node.body
                            if isinstance(item, ast.AnnAssign)
                            and isinstance(item.target, ast.Name)
                            and not _is_init_var(item.annotation)
                        )
                        if field_count > max_fields:
                            count += 1
                            if len(samples) < _MAX_SAMPLES:
                                samples.append(
                                    f"{rel_posix}: {class_name} has {field_count} declared fields "
                                    f"(threshold {max_fields}) — forbidden by {name!r}"
                                )
                        break  # report once per class per file

            # public_api_only — imports of <package>.* are only allowed
            # via the explicitly listed allowed_paths (exact module match).
            # Used to enforce public-API discipline when consuming an
            # extracted library — prevents deep imports that bypass the
            # contract (e.g. `from foo.runners.subprocess_runner import _x`
            # when only `from foo.runners import HttpRunner` is allowed).
            if "public_api_only" in rule:
                cfg = rule["public_api_only"]
                pkg: str = cfg.get("package", "")
                allowed: set[str] = set(cfg.get("allowed_paths") or [])
                if pkg and allowed:
                    pkg_dot = pkg + "."
                    for node in ast.walk(tree):
                        mod = None
                        lineno = 0
                        if isinstance(node, ast.Import):
                            for alias in node.names:
                                if alias.name == pkg or alias.name.startswith(pkg_dot):  # noqa: SIM102 (combined line would exceed the line limit)
                                    if alias.name not in allowed:
                                        mod = alias.name
                                        lineno = node.lineno
                                        break
                        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:  # noqa: SIM102 (inner condition is documented separately)
                            if node.module == pkg or node.module.startswith(pkg_dot):  # noqa: SIM102 (combined line would exceed the line limit)
                                if node.module not in allowed:
                                    mod = node.module
                                    lineno = node.lineno
                        if mod:
                            count += 1
                            if len(samples) < _MAX_SAMPLES:
                                samples.append(
                                    f"{rel_posix}:{lineno}: deep import {mod!r} from {pkg!r} — "
                                    f"only public API allowed: {sorted(allowed)}"
                                )
                            break

    return DetectorResult(count=count, samples=samples)


def _is_init_var(annotation: ast.expr | None) -> bool:
    """True if the annotation is InitVar[...] (dataclass init-only field, not stored)."""
    if annotation is None:
        return False
    if isinstance(annotation, ast.Subscript):
        v = annotation.value
        if isinstance(v, ast.Name) and v.id == "InitVar":
            return True
        if isinstance(v, ast.Attribute) and v.attr == "InitVar":
            return True
    return isinstance(annotation, ast.Name) and annotation.id == "InitVar"


# ── S1: layer boundary violations ────────────────────────────────────────────

def detect_s1(context: AuditContext) -> DetectorResult:
    if context.graph is None or context.graph.import_graph is None:
        return DetectorResult(count=0, samples=[])

    rules = _parse_layer_rules(context.config)
    if not rules:
        return DetectorResult(count=0, samples=[])

    graph = context.graph.import_graph
    samples: list[str] = []
    count = 0

    for rel_path, imported_modules in graph.imports.items():
        # Which layer does this file belong to?
        src_layer = _find_layer(rel_path, rules)
        if src_layer is None:
            continue
        forbidden_globs: list[str] = src_layer.get("may_not_import") or []
        if not forbidden_globs:
            continue

        for mod_name in sorted(imported_modules):
            # Resolve the imported module to a file path in our repo
            imported_path = graph.module_to_path.get(mod_name)
            if imported_path is None:
                # External dependency — not subject to layer rules
                continue
            if _any_glob(imported_path, forbidden_globs):
                count += 1
                if len(samples) < _MAX_SAMPLES:
                    src_layer_name = src_layer.get("name", "?")
                    imp_str = f"{rel_path.as_posix()} → {imported_path.as_posix()}"
                    samples.append(
                        f"[{src_layer_name}] {imp_str}"
                    )

    return DetectorResult(count=count, samples=samples)


def _find_layer(rel_path: Path, rules: list[dict]) -> dict | None:
    """Return the first layer whose glob matches rel_path, or None."""
    for rule in rules:
        globs = rule.get("glob") or rule.get("globs") or []
        if isinstance(globs, str):
            globs = [globs]
        if _any_glob(rel_path, globs):
            return rule
    return None


# ── S2: mutual imports ────────────────────────────────────────────────────────

def detect_s2(context: AuditContext) -> DetectorResult:
    """Flag pairs of modules that import each other at runtime.

    Only runtime imports are checked (TYPE_CHECKING-guarded imports are
    excluded).  The pair is reported once, with the module containing the
    first alphabetical import listed first.
    """
    if context.graph is None or context.graph.import_graph is None:
        return DetectorResult(count=0, samples=[])

    graph = context.graph.import_graph
    # Build module-name → module-name edges (intra-repo only)
    local_modules = graph.all_local_modules()
    # mod_name -> set of mod_names it imports (local only)
    runtime_edges: dict[str, set[str]] = {}
    for rel_path, imports in graph.imports.items():
        mod = graph.path_to_module.get(rel_path)
        if not mod:
            continue
        local_imports = set()
        for imp in imports:
            # Match exact or as prefix (e.g. "ops.adapters" imports "ops.adapters.plane")
            if imp in local_modules:
                local_imports.add(imp)
            else:
                # Check if any local module starts with imp + "."
                for local in local_modules:
                    if local.startswith(imp + ".") or local == imp:
                        local_imports.add(local)
        runtime_edges[mod] = local_imports

    samples: list[str] = []
    count = 0
    seen: set[frozenset[str]] = set()

    for mod_a, imports_a in sorted(runtime_edges.items()):
        for mod_b in sorted(imports_a):
            if mod_b == mod_a:  # self-import from relative resolution
                continue
            if mod_b not in runtime_edges:
                continue
            if mod_a in runtime_edges.get(mod_b, set()):
                pair = frozenset({mod_a, mod_b})
                if pair in seen:
                    continue
                seen.add(pair)
                count += 1
                if len(samples) < _MAX_SAMPLES:
                    path_a = graph.module_to_path.get(mod_a, Path(mod_a))
                    path_b = graph.module_to_path.get(mod_b, Path(mod_b))
                    samples.append(f"{path_a.as_posix()} ↔ {path_b.as_posix()}")

    return DetectorResult(count=count, samples=samples)


# ── S3: test-only imports in production code ──────────────────────────────────

def _is_test_module(name: str) -> bool:
    """True if the top-level component of a module name is test-related."""
    top = name.split(".")[0]
    return top in {"tests", "test"} or top.startswith("test_")


def detect_s3(context: AuditContext) -> DetectorResult:
    """Flag production modules that import from test packages or test_* modules.

    Test utilities must not leak into src/: shared helpers should live in
    src/ or be exposed via conftest.py.
    """
    if context.graph is None or context.graph.ast_forest is None:
        return DetectorResult(count=0, samples=[])

    samples: list[str] = []
    count = 0

    for path, tree, _src in context.graph.ast_forest.items():
        rel = path.relative_to(context.repo_root).as_posix()
        for node in ast.walk(tree):
            module_name: str | None = None
            lineno: int = 0
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if _is_test_module(alias.name):
                        module_name = alias.name
                        lineno = node.lineno
                        break
            elif isinstance(node, ast.ImportFrom):  # noqa: SIM102 (inner condition is documented separately)
                if node.module and _is_test_module(node.module):
                    module_name = node.module
                    lineno = node.lineno
            if module_name:
                count += 1
                if len(samples) < _MAX_SAMPLES:
                    samples.append(f"{rel}:{lineno}: imports {module_name!r}")

    return DetectorResult(count=count, samples=samples)


# ── S4: missing venv guard in tests/conftest.py ────────────────────────────────

_VENV_GUARD_MARKERS = ("sys.prefix", "_EXPECTED_VENV", "ACTIVE_PREFIX", "active_prefix")


def detect_s4(context: AuditContext) -> DetectorResult:
    """Flag repos whose tests/conftest.py lacks a venv guard.

    A valid guard checks that the active Python environment matches the repo's
    own .venv, preventing silent test runs against the wrong package set.
    Skipped when tests_root does not exist (no tests directory).
    """
    tests_root = context.tests_root
    if tests_root is None or not tests_root.is_dir():
        return DetectorResult(count=0, samples=[])

    # Check both tests_root/conftest.py and repo_root/conftest.py — some repos
    # put the guard at the project root when pytest rootdir is the repo root.
    candidates = [tests_root / "conftest.py", context.repo_root / "conftest.py"]
    for candidate in candidates:
        if candidate.exists():
            try:
                content = candidate.read_text(encoding="utf-8")
            except OSError:
                continue
            if any(marker in content for marker in _VENV_GUARD_MARKERS):
                return DetectorResult(count=0, samples=[])

    # Neither candidate has a guard
    conftest = tests_root / "conftest.py"
    if not conftest.exists():
        root_conftest = context.repo_root / "conftest.py"
        if not root_conftest.exists():
            rel = conftest.relative_to(context.repo_root).as_posix()
            return DetectorResult(count=1, samples=[f"{rel}: file missing — add conftest.py with venv guard"])

    rel = conftest.relative_to(context.repo_root).as_posix() if conftest.exists() else "conftest.py"
    return DetectorResult(
        count=1,
        samples=[f"{rel}: no venv guard — add sys.prefix / _EXPECTED_VENV check"],
    )


# ── H1: hexagonal architecture layer ordering ─────────────────────────────────

def _parse_hex_layers(config: dict) -> list[dict]:
    arch = config.get("architecture") or {}
    return list(arch.get("hex") or [])


def detect_h1(context: AuditContext) -> DetectorResult:
    """Flag imports that violate hexagonal architecture layer ordering.

    Layers are declared in ``.custodian.yaml`` under ``architecture.hex`` as an
    ordered list from innermost (domain) to outermost (infrastructure).  Each
    layer may only import from layers with a *lower index* (earlier in the list).
    A domain module importing from application or infrastructure is a violation.

    This is more opinionated and concise than S1's explicit ``may_not_import``
    lists: the dependency direction is encoded by list position, not enumeration.
    """
    if context.graph is None or context.graph.import_graph is None:
        return DetectorResult(count=0, samples=[])

    hex_layers = _parse_hex_layers(context.config)
    if not hex_layers:
        return DetectorResult(count=0, samples=[])

    graph = context.graph.import_graph
    samples: list[str] = []
    count = 0

    # Build index: path → layer index
    def _layer_index(rel_path: Path) -> int | None:
        for idx, layer in enumerate(hex_layers):
            globs = layer.get("glob") or layer.get("globs") or []
            if isinstance(globs, str):
                globs = [globs]
            if _any_glob(rel_path, globs):
                return idx
        return None

    for rel_path, imported_modules in graph.imports.items():
        src_idx = _layer_index(rel_path)
        if src_idx is None:
            continue

        for mod_name in sorted(imported_modules):
            imported_path = graph.module_to_path.get(mod_name)
            if imported_path is None:
                continue
            imp_idx = _layer_index(imported_path)
            if imp_idx is None:
                continue
            # Violation: importing from a layer with HIGHER index (outer importing inner is OK;
            # inner importing outer is not)
            if imp_idx > src_idx:
                count += 1
                if len(samples) < _MAX_SAMPLES:
                    src_name = hex_layers[src_idx].get("name", str(src_idx))
                    imp_name = hex_layers[imp_idx].get("name", str(imp_idx))
                    samples.append(
                        f"[{src_name}→{imp_name}] {rel_path.as_posix()} imports {imported_path.as_posix()}"
                    )

    return DetectorResult(count=count, samples=samples)
