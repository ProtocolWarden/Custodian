# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
"""Tests for D8 (inconsistent return paths — value return with implicit None fall-through)."""
from __future__ import annotations

import ast
import textwrap
from pathlib import Path

from custodian.audit_kit.detector import AnalysisGraph, AuditContext
from custodian.audit_kit.passes.ast_forest import AstForest
from custodian.audit_kit.detectors.dead_code import detect_d8


def _ctx(tmp_path: Path, src_files: dict[str, str], config: dict | None = None) -> AuditContext:
    src_root = tmp_path / "src"
    forest = AstForest()
    for rel, content in src_files.items():
        p = src_root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        text = textwrap.dedent(content)
        p.write_text(text, encoding="utf-8")
        try:
            forest.trees[p] = ast.parse(text)
            forest.sources[p] = text
        except SyntaxError:
            pass
    graph = AnalysisGraph(ast_forest=forest)
    return AuditContext(
        repo_root=tmp_path,
        src_root=src_root,
        tests_root=tmp_path / "tests",
        config=config or {},
        plugin_modules=[],
        graph=graph,
    )


class TestD8:
    def test_missing_return_on_else_path_flagged(self, tmp_path):
        ctx = _ctx(tmp_path, {"m.py": """
            def find(items, target):
                for item in items:
                    if item == target:
                        return item
            # falls off end when target not found
        """})
        result = detect_d8(ctx)
        assert result.count == 1
        assert "find" in result.samples[0]

    def test_all_paths_return_not_flagged(self, tmp_path):
        ctx = _ctx(tmp_path, {"m.py": """
            def get_status(active):
                if active:
                    return "on"
                else:
                    return "off"
        """})
        assert detect_d8(ctx).count == 0

    def test_void_function_not_flagged(self, tmp_path):
        ctx = _ctx(tmp_path, {"m.py": """
            def process(items):
                for item in items:
                    print(item)
        """})
        assert detect_d8(ctx).count == 0

    def test_annotated_none_return_not_flagged(self, tmp_path):
        ctx = _ctx(tmp_path, {"m.py": """
            def mutate(x) -> None:
                if x:
                    return
        """})
        assert detect_d8(ctx).count == 0

    def test_while_true_loop_not_flagged(self, tmp_path):
        ctx = _ctx(tmp_path, {"m.py": """
            def prompt(choices):
                while True:
                    raw = input("> ")
                    if raw in choices:
                        return raw
        """})
        assert detect_d8(ctx).count == 0

    def test_with_block_containing_return_not_flagged(self, tmp_path):
        ctx = _ctx(tmp_path, {"m.py": """
            def load(path):
                with open(path) as f:
                    return f.read()
        """})
        assert detect_d8(ctx).count == 0

    def test_if_else_with_returns_not_flagged(self, tmp_path):
        ctx = _ctx(tmp_path, {"m.py": """
            def compute(x):
                if x > 0:
                    return x * 2
                elif x < 0:
                    return -x
                else:
                    return 0
        """})
        assert detect_d8(ctx).count == 0

    def test_explicit_none_return_clears_finding(self, tmp_path):
        ctx = _ctx(tmp_path, {"m.py": """
            def maybe_find(items, target):
                for item in items:
                    if item == target:
                        return item
                return None
        """})
        assert detect_d8(ctx).count == 0

    def test_exclude_paths(self, tmp_path):
        ctx = _ctx(tmp_path, {"legacy/m.py": """
            def find(items, target):
                if items:
                    return items[0]
        """}, config={"audit": {"exclude_paths": {"D8": ["src/legacy/**"]}}})
        assert detect_d8(ctx).count == 0

    def test_abstractmethod_not_flagged(self, tmp_path):
        ctx = _ctx(tmp_path, {"m.py": """
            from abc import abstractmethod
            class Base:
                @abstractmethod
                def compute(self, x):
                    pass
        """})
        assert detect_d8(ctx).count == 0
