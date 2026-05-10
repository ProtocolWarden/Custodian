# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
"""AST forest analysis pass.

Pre-parses every .py file under src_root into an ast.Module tree.
Detectors that need AST-level analysis (U-class stubs, etc.) use this
rather than parsing files individually so the cost is paid once.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class AstForest:
    """Pre-parsed ASTs for all .py files under src_root.

    Attributes:
        trees:   path (absolute) → parsed ast.Module
        sources: path (absolute) → raw source text (for line context)
    """
    trees: dict[Path, ast.Module] = field(default_factory=dict)
    sources: dict[Path, str] = field(default_factory=dict)

    def items(self):
        """Yield (path, tree, source) for every successfully parsed file."""
        for path, tree in self.trees.items():
            yield path, tree, self.sources.get(path, "")


def build_ast_forest(src_root: Path) -> AstForest:
    """Parse every .py file under src_root. Files that fail to parse are skipped."""
    forest = AstForest()
    for path in sorted(src_root.rglob("*.py")):
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
            tree = ast.parse(text, filename=str(path))
        except (OSError, SyntaxError, UnicodeDecodeError):
            continue
        forest.trees[path] = tree
        forest.sources[path] = text
    return forest
