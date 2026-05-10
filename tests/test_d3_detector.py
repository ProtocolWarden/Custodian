# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
"""Tests for D3 — functions that never return normally (missing -> NoReturn)."""
from __future__ import annotations

import ast
import textwrap
from pathlib import Path

from custodian.audit_kit.detector import AnalysisGraph, AuditContext
from custodian.audit_kit.detectors.dead_code import detect_d3
from custodian.audit_kit.passes.ast_forest import AstForest


def _forest(src: str, tmp_path: Path, name: str = "module.py") -> AstForest:
    src_root = tmp_path / "src"
    src_root.mkdir(parents=True, exist_ok=True)
    path = src_root / name
    src = textwrap.dedent(src)
    path.write_text(src, encoding="utf-8")
    tree = ast.parse(src)
    forest = AstForest()
    forest.trees[path] = tree
    forest.sources[path] = src
    return forest


def _ctx(tmp_path: Path, forest: AstForest) -> AuditContext:
    return AuditContext(
        repo_root=tmp_path,
        src_root=tmp_path / "src",
        tests_root=tmp_path / "tests",
        config={},
        plugin_modules=[],
        graph=AnalysisGraph(ast_forest=forest),
    )


class TestD3:
    def test_no_forest_returns_zero(self, tmp_path):
        ctx = _ctx(tmp_path, AstForest())
        ctx.graph = AnalysisGraph(ast_forest=None)
        assert detect_d3(ctx).count == 0

    def test_always_raises_flagged(self, tmp_path):
        f = _forest("""
            def die(msg):
                raise RuntimeError(msg)
        """, tmp_path)
        assert detect_d3(_ctx(tmp_path, f)).count == 1

    def test_calls_sys_exit_flagged(self, tmp_path):
        f = _forest("""
            import sys
            def abort():
                sys.exit(1)
        """, tmp_path)
        assert detect_d3(_ctx(tmp_path, f)).count == 1

    def test_calls_exit_flagged(self, tmp_path):
        f = _forest("""
            def abort():
                exit(1)
        """, tmp_path)
        assert detect_d3(_ctx(tmp_path, f)).count == 1

    def test_normal_return_not_flagged(self, tmp_path):
        f = _forest("""
            def foo():
                return 42
        """, tmp_path)
        assert detect_d3(_ctx(tmp_path, f)).count == 0

    def test_conditional_raise_not_flagged(self, tmp_path):
        # only one branch raises — fallthrough possible
        f = _forest("""
            def check(x):
                if x < 0:
                    raise ValueError
                return x
        """, tmp_path)
        assert detect_d3(_ctx(tmp_path, f)).count == 0

    def test_all_branches_raise_flagged(self, tmp_path):
        f = _forest("""
            def strict(x):
                if x < 0:
                    raise ValueError("negative")
                else:
                    raise TypeError("not negative")
        """, tmp_path)
        assert detect_d3(_ctx(tmp_path, f)).count == 1

    def test_already_annotated_noreturn_excluded(self, tmp_path):
        f = _forest("""
            from typing import NoReturn
            def die(msg: str) -> NoReturn:
                raise RuntimeError(msg)
        """, tmp_path)
        assert detect_d3(_ctx(tmp_path, f)).count == 0

    def test_annotated_never_excluded(self, tmp_path):
        f = _forest("""
            from typing import Never
            def die() -> Never:
                raise SystemExit(1)
        """, tmp_path)
        assert detect_d3(_ctx(tmp_path, f)).count == 0

    def test_abstractmethod_excluded(self, tmp_path):
        f = _forest("""
            from abc import abstractmethod
            class Base:
                @abstractmethod
                def fail(self):
                    raise NotImplementedError
        """, tmp_path)
        assert detect_d3(_ctx(tmp_path, f)).count == 0

    def test_async_function_flagged(self, tmp_path):
        f = _forest("""
            async def boom():
                raise RuntimeError("async failure")
        """, tmp_path)
        assert detect_d3(_ctx(tmp_path, f)).count == 1

    def test_sample_text_contains_function_name(self, tmp_path):
        f = _forest("""
            def fatal_error(msg):
                raise SystemExit(msg)
        """, tmp_path)
        result = detect_d3(_ctx(tmp_path, f))
        assert result.count == 1
        assert "fatal_error" in result.samples[0]
        assert "NoReturn" in result.samples[0]

    def test_try_all_handlers_raise_flagged(self, tmp_path):
        f = _forest("""
            def risky():
                try:
                    raise ValueError
                except ValueError:
                    raise RuntimeError("wrapped")
        """, tmp_path)
        assert detect_d3(_ctx(tmp_path, f)).count == 1

    def test_try_handler_returns_not_flagged(self, tmp_path):
        f = _forest("""
            def safe():
                try:
                    raise ValueError
                except ValueError:
                    return -1
        """, tmp_path)
        assert detect_d3(_ctx(tmp_path, f)).count == 0

    def test_if_branches_return_then_raise_not_flagged(self, tmp_path):
        f = _forest("""
            def __getattr__(name: str):
                if name == "Foo":
                    return Foo
                if name == "Bar":
                    return Bar
                raise AttributeError(name)
        """, tmp_path)
        assert detect_d3(_ctx(tmp_path, f)).count == 0

    def test_single_raise_no_return_flagged(self, tmp_path):
        f = _forest("""
            def always_fails():
                raise RuntimeError("always")
        """, tmp_path)
        assert detect_d3(_ctx(tmp_path, f)).count == 1
