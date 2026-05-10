# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
"""Tests for D10 detector: async def without await."""
from __future__ import annotations

import ast
import textwrap
from pathlib import Path

from custodian.audit_kit.detector import AnalysisGraph, AuditContext
from custodian.audit_kit.detectors.dead_code import detect_d10
from custodian.audit_kit.passes.ast_forest import AstForest


def _forest_from_source(src: str, tmp_path: Path, name: str = "module.py") -> AstForest:
    src_root = tmp_path / "src"
    src_root.mkdir(parents=True, exist_ok=True)
    path = src_root / name
    text = textwrap.dedent(src)
    path.write_text(text, encoding="utf-8")
    forest = AstForest()
    forest.trees[path] = ast.parse(text)
    forest.sources[path] = text
    return forest


def _ctx(tmp_path: Path, forest: AstForest, config: dict | None = None) -> AuditContext:
    return AuditContext(
        repo_root=tmp_path,
        src_root=tmp_path / "src",
        tests_root=tmp_path / "tests",
        config=config or {},
        plugin_modules=[],
        graph=AnalysisGraph(ast_forest=forest),
    )


class TestD10:
    def test_no_forest_returns_zero(self, tmp_path):
        ctx = AuditContext(
            repo_root=tmp_path,
            src_root=tmp_path / "src",
            tests_root=tmp_path / "tests",
            config={},
            plugin_modules=[],
            graph=AnalysisGraph(ast_forest=None),
        )
        assert detect_d10(ctx).count == 0

    def test_async_with_await_not_flagged(self, tmp_path):
        forest = _forest_from_source("""
            async def fetch():
                result = await some_coro()
                return result
        """, tmp_path)
        assert detect_d10(_ctx(tmp_path, forest)).count == 0

    def test_async_without_await_flagged(self, tmp_path):
        forest = _forest_from_source("""
            async def do_sync_work():
                x = 1 + 1
                return x
        """, tmp_path)
        result = detect_d10(_ctx(tmp_path, forest))
        assert result.count == 1
        assert "do_sync_work" in result.samples[0]

    def test_stub_body_not_flagged(self, tmp_path):
        forest = _forest_from_source("""
            async def placeholder():
                pass
        """, tmp_path)
        assert detect_d10(_ctx(tmp_path, forest)).count == 0

    def test_ellipsis_stub_not_flagged(self, tmp_path):
        forest = _forest_from_source("""
            async def placeholder(): ...
        """, tmp_path)
        assert detect_d10(_ctx(tmp_path, forest)).count == 0

    def test_abstractmethod_not_flagged(self, tmp_path):
        forest = _forest_from_source("""
            from abc import abstractmethod

            class Base:
                @abstractmethod
                async def act(self) -> None: ...
        """, tmp_path)
        assert detect_d10(_ctx(tmp_path, forest)).count == 0

    def test_async_generator_with_yield_not_flagged(self, tmp_path):
        forest = _forest_from_source("""
            async def stream():
                yield 1
                yield 2
        """, tmp_path)
        assert detect_d10(_ctx(tmp_path, forest)).count == 0

    def test_fastapi_route_not_flagged(self, tmp_path):
        forest = _forest_from_source("""
            @router.get("/items")
            async def list_items():
                return db.query_all()
        """, tmp_path)
        assert detect_d10(_ctx(tmp_path, forest)).count == 0

    def test_on_event_handler_not_flagged(self, tmp_path):
        forest = _forest_from_source("""
            @app.on_event("startup")
            async def startup():
                cache.warm()
        """, tmp_path)
        assert detect_d10(_ctx(tmp_path, forest)).count == 0

    def test_asynccontextmanager_not_flagged(self, tmp_path):
        forest = _forest_from_source("""
            from contextlib import asynccontextmanager

            @asynccontextmanager
            async def managed():
                setup()
                yield
                teardown()
        """, tmp_path)
        assert detect_d10(_ctx(tmp_path, forest)).count == 0

    def test_dunder_aenter_not_flagged(self, tmp_path):
        forest = _forest_from_source("""
            class Ctx:
                async def __aenter__(self):
                    return self
        """, tmp_path)
        assert detect_d10(_ctx(tmp_path, forest)).count == 0

    def test_exclude_paths_respected(self, tmp_path):
        forest = _forest_from_source("""
            async def no_await():
                return 42
        """, tmp_path)
        config = {"audit": {"exclude_paths": {"D10": ["src/module.py"]}}}
        assert detect_d10(_ctx(tmp_path, forest, config)).count == 0

    def test_overload_not_flagged(self, tmp_path):
        forest = _forest_from_source("""
            from typing import overload

            @overload
            async def convert(x: int) -> str: ...
        """, tmp_path)
        assert detect_d10(_ctx(tmp_path, forest)).count == 0
