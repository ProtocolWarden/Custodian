# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
"""Symbol-index analysis pass.

Builds two sets from every .py file under src_root:

  defined_names   — all function, class, and module-level variable names
                    that are *defined* in the codebase (ast.FunctionDef,
                    ast.AsyncFunctionDef, ast.ClassDef, module-scope
                    ast.Assign targets, ast.AnnAssign targets).

  all_text_tokens — every identifier-like token that appears anywhere in
                    any source file (split on non-identifier chars).
                    Used by G1 to determine whether a name mentioned in a
                    TODO comment has been completely removed from the source.
"""
from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

_IDENT_SPLIT = re.compile(r"[^A-Za-z0-9_]+")
_COMMENT_RE = re.compile(r"#[^\n]*")  # strip line comments before tokenizing


@dataclass
class SymbolIndex:
    defined_names: set[str] = field(default_factory=set)
    all_text_tokens: set[str] = field(default_factory=set)


def build_symbol_index(src_root: Path) -> SymbolIndex:
    """Walk every .py file under src_root and build the symbol index."""
    idx = SymbolIndex()
    for path in sorted(src_root.rglob("*.py")):
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
            tree = ast.parse(text, filename=str(path))
        except (OSError, SyntaxError, UnicodeDecodeError):
            continue
        _collect_definitions(tree, idx)
        # Strip comments before tokenizing so words that appear ONLY in
        # comments (e.g. a TODO mentioning a deleted class) are not indexed.
        code_text = _COMMENT_RE.sub("", text)
        for token in _IDENT_SPLIT.split(code_text):
            if token:
                idx.all_text_tokens.add(token)
    return idx


def _collect_definitions(tree: ast.Module, idx: SymbolIndex) -> None:
    # Top-level definitions
    for stmt in tree.body:
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            idx.defined_names.add(stmt.name)
        elif isinstance(stmt, ast.Assign):
            for target in stmt.targets:
                if isinstance(target, ast.Name):
                    idx.defined_names.add(target.id)
        elif isinstance(stmt, ast.AnnAssign):
            if isinstance(stmt.target, ast.Name):
                idx.defined_names.add(stmt.target.id)

    # Class-level definitions (methods, class vars)
    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef):
            continue
        for item in node.body:
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                idx.defined_names.add(item.name)
            elif isinstance(item, ast.AnnAssign) and isinstance(item.target, ast.Name):
                idx.defined_names.add(item.target.id)
