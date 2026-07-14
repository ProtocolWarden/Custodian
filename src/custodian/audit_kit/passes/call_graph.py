# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
"""Call-graph analysis pass.

Builds a lightweight static call-graph by walking AST nodes across all
source files.  Covers only statically-resolvable calls — dynamic dispatch
via ``getattr``, higher-order functions passed as arguments, and calls
through variables are not captured.  This is intentional: the false-
positive cost of flagging a "dead" function that is actually called
dynamically is higher than the false-negative cost of missing it.

Definitions collected:
  - Module-level function definitions (``def``/``async def`` at module scope)
  - Named functions inside classes (methods)

Calls collected:
  - Direct name calls: ``foo()``
  - Attribute calls: ``obj.bar()`` — the attribute name ``bar`` is recorded
    (without receiver type info)

Attribute accesses collected (for dead-field detection):
  - ``obj.name`` attribute loads — the attribute name is recorded
"""
from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class CallGraph:
    """Lightweight static call-graph derived from AST walks.

    Attributes:
        module_functions: names of module-level function definitions (non-method)
        all_defined:      all function/method names defined anywhere in src
        called_names:     all bare-name call targets (``foo()`` → ``"foo"``)
        called_attrs:     all attribute call targets (``x.bar()`` → ``"bar"``)
        accessed_attrs:   all attribute *loads* (``x.baz`` → ``"baz"``)
        defined_in_all:   names exported via ``__all__`` (excluded from dead checks)
        decorated_names:  names used as decorator targets (treated as called)
    """
    module_functions: set[str] = field(default_factory=set)
    all_defined: set[str] = field(default_factory=set)
    called_names: set[str] = field(default_factory=set)
    called_attrs: set[str] = field(default_factory=set)
    accessed_attrs: set[str] = field(default_factory=set)
    defined_in_all: set[str] = field(default_factory=set)
    decorated_names: set[str] = field(default_factory=set)
    framework_decorated: set[str] = field(default_factory=set)
    constructed_names: set[str] = field(default_factory=set)
    kw_arg_names: set[str] = field(default_factory=set)  # keyword arg names used in calls
    dynamic_getattr_classes: set[str] = field(default_factory=set)  # classes with getattr(self, var) patterns
    model_validate_classes: set[str] = field(default_factory=set)  # classes deserialized via model_validate*()


def build_call_graph(src_root: Path, extra_roots: list[Path] | None = None) -> CallGraph:
    """Walk every .py file under src_root (and extra_roots) and build the call-graph.

    extra_roots are scanned for attribute/call usages only — their definitions
    are not added to module_functions or framework_decorated so D1/D2 checks
    remain src-only.
    """
    cg = CallGraph()
    for path in sorted(src_root.rglob("*.py")):
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
            tree = ast.parse(text, filename=str(path))
        except (OSError, SyntaxError, UnicodeDecodeError):
            continue
        _collect_from_module(tree, cg)
    for extra_root in (extra_roots or []):
        if not extra_root.is_dir():
            continue
        for path in sorted(extra_root.rglob("*.py")):
            if not path.is_file():
                continue
            try:
                text = path.read_text(encoding="utf-8")
                tree = ast.parse(text, filename=str(path))
            except (OSError, SyntaxError, UnicodeDecodeError):
                continue
            _collect_usages_only(tree, cg)
    return cg


def _collect_usages_only(tree: ast.Module, cg: CallGraph) -> None:
    """Collect only call sites and attribute accesses from extra (test) files."""
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            for base in node.bases:
                if isinstance(base, ast.Name):
                    cg.constructed_names.add(base.id)
                elif isinstance(base, ast.Attribute):
                    cg.constructed_names.add(base.attr)
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name):
                cg.called_names.add(func.id)
                cg.constructed_names.add(func.id)
            elif isinstance(func, ast.Attribute):
                cg.called_attrs.add(func.attr)
            elif isinstance(func, ast.Subscript) and isinstance(func.value, ast.Name):
                cg.called_names.add(func.value.id)
                cg.constructed_names.add(func.value.id)
            # getattr(obj, "field") — string-based attribute access
            if (
                isinstance(func, ast.Name) and func.id == "getattr"
                and len(node.args) >= 2
                and isinstance(node.args[1], ast.Constant)
                and isinstance(node.args[1].value, str)
            ):
                cg.accessed_attrs.add(node.args[1].value)
            # default_factory=ClassName, factory=ClassName etc. — class passed as callable
            for kw in node.keywords:
                if isinstance(kw.value, ast.Name):
                    cg.constructed_names.add(kw.value.id)
                if kw.arg:  # keyword arg name — Model(field=value) records "field"
                    cg.kw_arg_names.add(kw.arg)
            if (
                isinstance(func, ast.Attribute)
                and func.attr.startswith("model_validate")
                and isinstance(func.value, ast.Name)
            ):
                cg.model_validate_classes.add(func.value.id)
        if isinstance(node, ast.Attribute) and isinstance(node.ctx, ast.Load):
            cg.accessed_attrs.add(node.attr)
            # ClassName.method(...) or EnumClass.MEMBER — treat as "class is in active use"
            if isinstance(node.value, ast.Name):
                cg.constructed_names.add(node.value.id)
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
            cg.called_names.add(node.id)


def _collect_from_module(tree: ast.Module, cg: CallGraph) -> None:
    _PURE_DECORATORS = frozenset({"staticmethod", "classmethod", "property", "override", "abstractmethod", "final"})

    # Module-level definitions (not nested inside a class/function)
    for stmt in tree.body:
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            cg.module_functions.add(stmt.name)
            for dec in stmt.decorator_list:
                dec_name = dec.id if isinstance(dec, ast.Name) else None
                if dec_name not in _PURE_DECORATORS:
                    cg.framework_decorated.add(stmt.name)
                    break
        if isinstance(stmt, ast.Assign):
            for target in stmt.targets:
                if isinstance(target, ast.Name) and target.id == "__all__":
                    if isinstance(stmt.value, (ast.List, ast.Tuple)):
                        for elt in stmt.value.elts:
                            if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                                cg.defined_in_all.add(elt.value)

    # All defined names (functions/methods anywhere)
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            cg.all_defined.add(node.name)
            # Decorator names are "uses" of those functions
            for dec in node.decorator_list:
                if isinstance(dec, ast.Name):
                    cg.decorated_names.add(dec.id)
                elif isinstance(dec, ast.Attribute):
                    cg.decorated_names.add(dec.attr)

    # Base class names — class Child(Base): means Base is actively used
    # Also detect getattr(self, variable) — dynamic field access; all class fields are live
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            for base in node.bases:
                if isinstance(base, ast.Name):
                    cg.constructed_names.add(base.id)
                elif isinstance(base, ast.Attribute):
                    cg.constructed_names.add(base.attr)
            for child in ast.walk(node):
                if not isinstance(child, ast.Call):
                    continue
                func = child.func
                if not (isinstance(func, ast.Name) and func.id == "getattr"):
                    continue
                if len(child.args) < 2:
                    continue
                receiver = child.args[0]
                key = child.args[1]
                if isinstance(receiver, ast.Name) and receiver.id == "self" and not isinstance(key, ast.Constant):
                    cg.dynamic_getattr_classes.add(node.name)
                    break

    # ClassName.model_validate*(...) — deserialized from external data; all fields are schema fields
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            if (
                isinstance(func, ast.Attribute)
                and func.attr.startswith("model_validate")
                and isinstance(func.value, ast.Name)
            ):
                cg.model_validate_classes.add(func.value.id)

    # All call sites, attribute accesses, and bare name references
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name):
                cg.called_names.add(func.id)
                cg.constructed_names.add(func.id)
            elif isinstance(func, ast.Attribute):
                cg.called_attrs.add(func.attr)
            elif isinstance(func, ast.Subscript) and isinstance(func.value, ast.Name):
                # Generic parameterized constructor: ClassName[T, U](...) — treat as construction
                cg.called_names.add(func.value.id)
                cg.constructed_names.add(func.value.id)
            # getattr(obj, "field") — string-based attribute access; treat as attribute read
            if (
                isinstance(func, ast.Name) and func.id == "getattr"
                and len(node.args) >= 2
                and isinstance(node.args[1], ast.Constant)
                and isinstance(node.args[1].value, str)
            ):
                cg.accessed_attrs.add(node.args[1].value)
            # default_factory=ClassName, factory=ClassName etc. — class passed as callable
            for kw in node.keywords:
                if isinstance(kw.value, ast.Name):
                    cg.constructed_names.add(kw.value.id)
                if kw.arg:  # keyword arg name — Model(field=value) records "field"
                    cg.kw_arg_names.add(kw.arg)
        if isinstance(node, ast.Attribute) and isinstance(node.ctx, ast.Load):
            cg.accessed_attrs.add(node.attr)
            # ClassName.method(...) or EnumClass.MEMBER — treat as "class is in active use"
            if isinstance(node.value, ast.Name):
                cg.constructed_names.add(node.value.id)
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
            cg.called_names.add(node.id)
