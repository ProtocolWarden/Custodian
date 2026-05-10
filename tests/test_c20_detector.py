# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
"""Tests for C20 (raise generic Exception/BaseException)."""
from __future__ import annotations

import ast
import textwrap
from pathlib import Path

from custodian.audit_kit.detector import AnalysisGraph, AuditContext
from custodian.audit_kit.code_health import detect_c20
from custodian.audit_kit.passes.ast_forest import AstForest


def _make_context(tmp_path: Path, src_files: dict[str, str], config: dict | None = None) -> AuditContext:
    src_root = tmp_path / "src"
    for rel, content in src_files.items():
        p = src_root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(textwrap.dedent(content), encoding="utf-8")
    forest = AstForest()
    for rel in src_files:
        p = src_root / rel
        text = p.read_text(encoding="utf-8")
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


class TestC20:
    def test_raise_exception_flagged(self, tmp_path):
        ctx = _make_context(tmp_path, {"m.py": """
            raise Exception("something went wrong")
        """})
        result = detect_c20(ctx)
        assert result.count == 1

    def test_raise_base_exception_flagged(self, tmp_path):
        ctx = _make_context(tmp_path, {"m.py": """
            raise BaseException("something went wrong")
        """})
        result = detect_c20(ctx)
        assert result.count == 1

    def test_raise_runtime_error_not_flagged(self, tmp_path):
        ctx = _make_context(tmp_path, {"m.py": """
            raise RuntimeError("something went wrong")
        """})
        result = detect_c20(ctx)
        assert result.count == 0

    def test_raise_value_error_not_flagged(self, tmp_path):
        ctx = _make_context(tmp_path, {"m.py": """
            raise ValueError("bad input")
        """})
        result = detect_c20(ctx)
        assert result.count == 0

    def test_bare_raise_not_flagged(self, tmp_path):
        # bare re-raise inside except handler
        ctx = _make_context(tmp_path, {"m.py": """
            try:
                pass
            except ValueError:
                raise
        """})
        result = detect_c20(ctx)
        assert result.count == 0

    def test_exclude_path_suppresses(self, tmp_path):
        ctx = _make_context(tmp_path, {"m.py": """
            raise Exception("bad")
        """}, config={"audit": {"exclude_paths": {"C20": ["src/m.py"]}}})
        result = detect_c20(ctx)
        assert result.count == 0
