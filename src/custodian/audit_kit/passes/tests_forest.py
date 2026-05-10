# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
"""Tests-forest analysis pass.

Pre-parses every .py file under tests_root into an ast.Module tree, mirroring
the ast_forest pass but scoped to the test directory.  Detectors that need
cross-reference information between src and tests (e.g. T1) use this pass
rather than parsing test files individually.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class TestsForest:
    """Pre-parsed ASTs for all .py files under tests_root."""
    trees: dict[Path, ast.Module] = field(default_factory=dict)
    sources: dict[Path, str] = field(default_factory=dict)

    def items(self):
        for path, tree in self.trees.items():
            yield path, tree, self.sources.get(path, "")


def build_tests_forest(tests_root: Path) -> TestsForest:
    """Parse every .py file under tests_root. Files that fail are skipped."""
    forest = TestsForest()
    if not tests_root.is_dir():
        return forest
    for path in sorted(tests_root.rglob("*.py")):
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
