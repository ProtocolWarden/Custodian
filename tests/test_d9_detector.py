# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
"""Tests for D9 (no-op try/except re-raise)."""
from __future__ import annotations

import ast
import textwrap
from pathlib import Path

from custodian.audit_kit.detector import AnalysisGraph, AuditContext
from custodian.audit_kit.passes.ast_forest import AstForest
from custodian.audit_kit.detectors.dead_code import detect_d9


def _ctx(tmp_path: Path, src: str, config: dict | None = None) -> AuditContext:
    src_root = tmp_path / "src"
    p = src_root / "m.py"
    p.parent.mkdir(parents=True, exist_ok=True)
    src = textwrap.dedent(src)
    p.write_text(src, encoding="utf-8")
    forest = AstForest()
    forest.trees[p] = ast.parse(src)
    forest.sources[p] = src
    graph = AnalysisGraph(ast_forest=forest)
    return AuditContext(
        repo_root=tmp_path,
        src_root=src_root,
        tests_root=tmp_path / "tests",
        config=config or {},
        plugin_modules=[],
        graph=graph,
    )


class TestD9:
    def test_single_handler_bare_reraise_flagged(self, tmp_path):
        ctx = _ctx(tmp_path, """
            def fn():
                try:
                    do_something()
                except Exception:
                    raise
        """)
        result = detect_d9(ctx)
        assert result.count == 1
        assert "re-raises" in result.samples[0]

    def test_handler_with_logging_not_flagged(self, tmp_path):
        ctx = _ctx(tmp_path, """
            def fn():
                try:
                    do_something()
                except Exception:
                    logger.error("oops")
                    raise
        """)
        assert detect_d9(ctx).count == 0

    def test_multi_handler_bare_reraise_not_flagged(self, tmp_path):
        """Bare reraise in one of multiple handlers is intentional filtering."""
        ctx = _ctx(tmp_path, """
            def fn():
                try:
                    do_something()
                except SpecificError:
                    raise
                except Exception:
                    logger.error("oops")
                    raise
        """)
        assert detect_d9(ctx).count == 0

    def test_raise_with_value_not_flagged(self, tmp_path):
        """raise SomeError(...) is not a bare reraise."""
        ctx = _ctx(tmp_path, """
            def fn():
                try:
                    do_something()
                except Exception as exc:
                    raise RuntimeError("wrapped") from exc
        """)
        assert detect_d9(ctx).count == 0

    def test_no_except_not_flagged(self, tmp_path):
        ctx = _ctx(tmp_path, """
            def fn():
                try:
                    do_something()
                finally:
                    cleanup()
        """)
        assert detect_d9(ctx).count == 0

    def test_handler_with_assignment_not_flagged(self, tmp_path):
        ctx = _ctx(tmp_path, """
            def fn():
                try:
                    do_something()
                except Exception as exc:
                    context["error"] = str(exc)
                    raise
        """)
        assert detect_d9(ctx).count == 0

    def test_multiple_no_op_handlers_in_file(self, tmp_path):
        ctx = _ctx(tmp_path, """
            def fn1():
                try:
                    a()
                except Exception:
                    raise

            def fn2():
                try:
                    b()
                except Exception:
                    raise
        """)
        result = detect_d9(ctx)
        assert result.count == 2

    def test_exclude_paths(self, tmp_path):
        src_root = tmp_path / "src"
        p = src_root / "legacy" / "m.py"
        p.parent.mkdir(parents=True, exist_ok=True)
        src = textwrap.dedent("""
            def fn():
                try:
                    do_something()
                except Exception:
                    raise
        """)
        p.write_text(src, encoding="utf-8")
        forest = AstForest()
        forest.trees[p] = ast.parse(src)
        forest.sources[p] = src
        graph = AnalysisGraph(ast_forest=forest)
        ctx = AuditContext(
            repo_root=tmp_path,
            src_root=src_root,
            tests_root=tmp_path / "tests",
            config={"audit": {"exclude_paths": {"D9": ["src/legacy/**"]}}},
            plugin_modules=[],
            graph=graph,
        )
        assert detect_d9(ctx).count == 0

    def test_nested_no_op_in_function(self, tmp_path):
        ctx = _ctx(tmp_path, """
            def outer():
                def inner():
                    pass
                try:
                    inner()
                except Exception:
                    raise
        """)
        result = detect_d9(ctx)
        assert result.count == 1
