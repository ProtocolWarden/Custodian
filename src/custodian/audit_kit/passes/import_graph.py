# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Velascat
"""Import graph analysis pass.

Builds a module-level import map for all .py files under src_root.
Imports inside ``if TYPE_CHECKING:`` blocks are recorded separately so
detectors that care only about runtime imports can ignore them.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ImportGraph:
    """Module-level import relationships across src_root.

    Attributes:
        imports:           rel_path (repo-relative) → set of imported module names
                           (runtime only; TYPE_CHECKING imports excluded).
        type_check_imports: rel_path → set of TYPE_CHECKING-only import names.
        module_to_path:    qualified module name → path relative to repo_root.
        path_to_module:    path relative to repo_root → qualified module name.
    """
    imports: dict[Path, set[str]] = field(default_factory=dict)
    type_check_imports: dict[Path, set[str]] = field(default_factory=dict)
    module_to_path: dict[str, Path] = field(default_factory=dict)
    path_to_module: dict[Path, str] = field(default_factory=dict)

    def runtime_imports(self, path: Path) -> set[str]:
        """Module names imported at runtime by the file at path (repo-relative)."""
        return self.imports.get(path, set())

    def all_local_modules(self) -> set[str]:
        return set(self.module_to_path)


def build_import_graph(src_root: Path, repo_root: Path) -> ImportGraph:
    """Parse every .py under src_root and build the import graph.

    Steps:
      1. Walk src_root to build path↔module name mappings.
      2. Re-walk to extract import statements, resolving relative imports.
         Imports under ``if TYPE_CHECKING:`` are kept separate.
    """
    graph = ImportGraph()

    # Pass 1: path <-> module name
    for path in sorted(src_root.rglob("*.py")):
        if not path.is_file():
            continue
        rel = path.relative_to(repo_root)
        parts = list(path.relative_to(src_root).with_suffix("").parts)
        if parts and parts[-1] == "__init__":
            parts = parts[:-1]
        module_name = ".".join(parts)
        if not module_name:
            continue
        graph.module_to_path[module_name] = rel
        graph.path_to_module[rel] = module_name

    # Pass 2: extract imports
    for path in sorted(src_root.rglob("*.py")):
        if not path.is_file():
            continue
        rel = path.relative_to(repo_root)
        current_module = graph.path_to_module.get(rel, "")
        current_pkg = current_module.rsplit(".", 1)[0] if "." in current_module else ""

        try:
            text = path.read_text(encoding="utf-8")
            tree = ast.parse(text)
        except (OSError, SyntaxError, UnicodeDecodeError):
            continue

        runtime: set[str] = set()
        type_check: set[str] = set()

        _collect_imports(tree.body, runtime, type_check, current_pkg)

        graph.imports[rel] = runtime
        graph.type_check_imports[rel] = type_check

    return graph


def _is_type_checking_guard(node: ast.stmt) -> bool:
    if not isinstance(node, ast.If):
        return False
    test = node.test
    if isinstance(test, ast.Name) and test.id == "TYPE_CHECKING":
        return True
    if isinstance(test, ast.Attribute) and test.attr == "TYPE_CHECKING":
        return True
    return False


def _collect_imports(
    stmts: list[ast.stmt],
    runtime: set[str],
    type_check: set[str],
    current_pkg: str,
    *,
    under_type_check: bool = False,
) -> None:
    target = type_check if under_type_check else runtime
    for stmt in stmts:
        if _is_type_checking_guard(stmt):
            # _is_type_checking_guard() returns True only for `if TYPE_CHECKING:` blocks.
            assert isinstance(stmt, ast.If)  # noqa: S101
            _collect_imports(
                stmt.body, runtime, type_check, current_pkg,
                under_type_check=True,
            )
            continue
        if isinstance(stmt, ast.Import):
            for alias in stmt.names:
                target.add(alias.name)
        elif isinstance(stmt, ast.ImportFrom):
            if stmt.level == 0:
                if stmt.module:
                    target.add(stmt.module)
            else:
                resolved = _resolve_relative(stmt.module, stmt.level, current_pkg)
                if resolved:
                    target.add(resolved)
        elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            # Don't recurse into functions/classes — only top-level imports matter
            # for cycle detection and layer checks
            pass
        elif isinstance(stmt, ast.If):
            _collect_imports(stmt.body, runtime, type_check, current_pkg,
                             under_type_check=under_type_check)
            _collect_imports(stmt.orelse, runtime, type_check, current_pkg,
                             under_type_check=under_type_check)


def _resolve_relative(module: str | None, level: int, current_pkg: str) -> str:
    parts = current_pkg.split(".") if current_pkg else []
    # level=1 → same package; level=2 → parent package; etc.
    base = parts[:max(0, len(parts) - (level - 1))]
    if module:
        return ".".join(base + module.split("."))
    return ".".join(base)
