# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
"""Tests for U-class (stub/unimplemented) detectors: U1, U2, U3."""
from __future__ import annotations

import ast
import textwrap
from pathlib import Path


from custodian.audit_kit.detector import AnalysisGraph, AuditContext
from custodian.audit_kit.detectors.stubs import detect_u1, detect_u2, detect_u3
from custodian.audit_kit.passes.ast_forest import AstForest


def _forest_from_source(src: str, tmp_path: Path, name: str = "module.py") -> AstForest:
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


def _make_context(tmp_path: Path, forest: AstForest) -> AuditContext:
    graph = AnalysisGraph(ast_forest=forest)
    return AuditContext(
        repo_root=tmp_path,
        src_root=tmp_path / "src",
        tests_root=tmp_path / "tests",
        config={},
        plugin_modules=[],
        graph=graph,
    )


# ── U1 tests ─────────────────────────────────────────────────────────────────

class TestU1:
    def test_no_forest_returns_zero(self, tmp_path):
        ctx = _make_context(tmp_path, AstForest())
        ctx.graph = AnalysisGraph(ast_forest=None)
        result = detect_u1(ctx)
        assert result.count == 0

    def test_plain_raise_not_implemented(self, tmp_path):
        forest = _forest_from_source("""
            def foo():
                raise NotImplementedError
        """, tmp_path)
        result = detect_u1(_make_context(tmp_path, forest))
        assert result.count == 1

    def test_raise_not_implemented_with_call(self, tmp_path):
        forest = _forest_from_source("""
            def foo():
                raise NotImplementedError("not done")
        """, tmp_path)
        result = detect_u1(_make_context(tmp_path, forest))
        assert result.count == 1

    def test_raise_with_docstring_still_flagged(self, tmp_path):
        forest = _forest_from_source("""
            def foo():
                "stub"
                raise NotImplementedError
        """, tmp_path)
        result = detect_u1(_make_context(tmp_path, forest))
        assert result.count == 1

    def test_abstractmethod_excluded(self, tmp_path):
        forest = _forest_from_source("""
            from abc import abstractmethod
            class Base:
                @abstractmethod
                def foo(self):
                    raise NotImplementedError
        """, tmp_path)
        result = detect_u1(_make_context(tmp_path, forest))
        assert result.count == 0

    def test_protocol_method_excluded(self, tmp_path):
        forest = _forest_from_source("""
            from typing import Protocol
            class MyProto(Protocol):
                def foo(self) -> None:
                    raise NotImplementedError
        """, tmp_path)
        result = detect_u1(_make_context(tmp_path, forest))
        assert result.count == 0

    def test_real_implementation_not_flagged(self, tmp_path):
        forest = _forest_from_source("""
            def foo():
                x = 1
                raise NotImplementedError
        """, tmp_path)
        result = detect_u1(_make_context(tmp_path, forest))
        assert result.count == 0

    def test_async_function_flagged(self, tmp_path):
        forest = _forest_from_source("""
            async def foo():
                raise NotImplementedError
        """, tmp_path)
        result = detect_u1(_make_context(tmp_path, forest))
        assert result.count == 1


# ── U2 tests ─────────────────────────────────────────────────────────────────

class TestU2:
    def test_ellipsis_only_body(self, tmp_path):
        forest = _forest_from_source("""
            def foo():
                ...
        """, tmp_path)
        result = detect_u2(_make_context(tmp_path, forest))
        assert result.count == 1

    def test_ellipsis_with_docstring(self, tmp_path):
        forest = _forest_from_source("""
            def foo():
                "docstring"
                ...
        """, tmp_path)
        result = detect_u2(_make_context(tmp_path, forest))
        assert result.count == 1

    def test_abstractmethod_excluded(self, tmp_path):
        forest = _forest_from_source("""
            from abc import abstractmethod
            class Base:
                @abstractmethod
                def foo(self): ...
        """, tmp_path)
        result = detect_u2(_make_context(tmp_path, forest))
        assert result.count == 0

    def test_overload_excluded(self, tmp_path):
        forest = _forest_from_source("""
            from typing import overload
            @overload
            def foo(x: int) -> int: ...
        """, tmp_path)
        result = detect_u2(_make_context(tmp_path, forest))
        assert result.count == 0

    def test_protocol_method_excluded(self, tmp_path):
        forest = _forest_from_source("""
            from typing import Protocol
            class Runnable(Protocol):
                def run(self) -> None: ...
        """, tmp_path)
        result = detect_u2(_make_context(tmp_path, forest))
        assert result.count == 0

    def test_real_function_not_flagged(self, tmp_path):
        forest = _forest_from_source("""
            def foo():
                return 42
        """, tmp_path)
        result = detect_u2(_make_context(tmp_path, forest))
        assert result.count == 0


# ── U3 tests ─────────────────────────────────────────────────────────────────

class TestU3:
    def test_docstring_only_flagged(self, tmp_path):
        forest = _forest_from_source("""
            def foo():
                "This function does something."
        """, tmp_path)
        result = detect_u3(_make_context(tmp_path, forest))
        assert result.count == 1

    def test_docstring_plus_pass_not_flagged(self, tmp_path):
        forest = _forest_from_source("""
            def foo():
                "This function does something."
                pass
        """, tmp_path)
        result = detect_u3(_make_context(tmp_path, forest))
        assert result.count == 0

    def test_no_docstring_not_flagged(self, tmp_path):
        forest = _forest_from_source("""
            def foo():
                pass
        """, tmp_path)
        result = detect_u3(_make_context(tmp_path, forest))
        assert result.count == 0

    def test_abstractmethod_excluded(self, tmp_path):
        forest = _forest_from_source("""
            from abc import abstractmethod
            class Base:
                @abstractmethod
                def foo(self):
                    "Abstract."
        """, tmp_path)
        result = detect_u3(_make_context(tmp_path, forest))
        assert result.count == 0

    def test_protocol_method_excluded(self, tmp_path):
        forest = _forest_from_source("""
            from typing import Protocol
            class MyProto(Protocol):
                def foo(self) -> None:
                    "Protocol method."
        """, tmp_path)
        result = detect_u3(_make_context(tmp_path, forest))
        assert result.count == 0

    def test_async_docstring_only_flagged(self, tmp_path):
        forest = _forest_from_source("""
            async def foo():
                "async stub"
        """, tmp_path)
        result = detect_u3(_make_context(tmp_path, forest))
        assert result.count == 1

    def test_except_handler_stub_excluded(self, tmp_path):
        forest = _forest_from_source("""
            try:
                from real_lib import Foo
            except Exception:
                class Foo:
                    def add(self, text: str) -> None:
                        "No-op add."
        """, tmp_path)
        result = detect_u3(_make_context(tmp_path, forest))
        assert result.count == 0
