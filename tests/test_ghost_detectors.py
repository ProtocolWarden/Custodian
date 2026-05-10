# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
"""Tests for symbol_index pass and G1 (stale TODO symbol references)."""
from __future__ import annotations

import textwrap
from pathlib import Path

from custodian.audit_kit.detector import AnalysisGraph, AuditContext
from custodian.audit_kit.detectors.ghost import detect_g1
from custodian.audit_kit.passes.symbol_index import build_symbol_index


def _write_src(src: str, tmp_path: Path, name: str = "module.py") -> None:
    src_root = tmp_path / "src"
    src_root.mkdir(parents=True, exist_ok=True)
    (src_root / name).write_text(textwrap.dedent(src), encoding="utf-8")


def _ctx(tmp_path: Path) -> AuditContext:
    src_root = tmp_path / "src"
    src_root.mkdir(parents=True, exist_ok=True)
    idx = build_symbol_index(src_root)
    return AuditContext(
        repo_root=tmp_path,
        src_root=src_root,
        tests_root=tmp_path / "tests",
        config={},
        plugin_modules=[],
        graph=AnalysisGraph(symbol_index=idx),
    )


class TestSymbolIndex:
    def test_empty_src_root(self, tmp_path):
        idx = build_symbol_index(tmp_path / "src")
        assert idx.defined_names == set()
        assert idx.all_text_tokens == set()

    def test_collects_function_name(self, tmp_path):
        _write_src("def my_func(): pass", tmp_path)
        idx = build_symbol_index(tmp_path / "src")
        assert "my_func" in idx.defined_names

    def test_collects_class_name(self, tmp_path):
        _write_src("class MyService: pass", tmp_path)
        idx = build_symbol_index(tmp_path / "src")
        assert "MyService" in idx.defined_names
        assert "MyService" in idx.all_text_tokens

    def test_collects_module_variable(self, tmp_path):
        _write_src("TIMEOUT = 30", tmp_path)
        idx = build_symbol_index(tmp_path / "src")
        assert "TIMEOUT" in idx.defined_names

    def test_all_text_tokens_includes_non_definitions(self, tmp_path):
        _write_src('x = "OldService"', tmp_path)
        idx = build_symbol_index(tmp_path / "src")
        assert "OldService" in idx.all_text_tokens

    def test_collects_method_name(self, tmp_path):
        _write_src("""
            class Foo:
                def run(self): pass
        """, tmp_path)
        idx = build_symbol_index(tmp_path / "src")
        assert "run" in idx.defined_names


class TestG1:
    def test_no_symbol_index_returns_zero(self, tmp_path):
        ctx = AuditContext(
            repo_root=tmp_path, src_root=tmp_path / "src",
            tests_root=tmp_path / "tests", config={}, plugin_modules=[],
            graph=AnalysisGraph(symbol_index=None),
        )
        assert detect_g1(ctx).count == 0

    def test_todo_with_present_symbol_not_flagged(self, tmp_path):
        _write_src("""
            class MyService:
                pass
            # TODO: update MyService to support streaming
        """, tmp_path)
        assert detect_g1(_ctx(tmp_path)).count == 0

    def test_todo_with_absent_camelcase_flagged(self, tmp_path):
        _write_src("""
            # TODO: remove OldService once migration is complete
            class NewService:
                pass
        """, tmp_path)
        assert detect_g1(_ctx(tmp_path)).count == 1

    def test_fixme_with_absent_symbol_flagged(self, tmp_path):
        _write_src("""
            # FIXME: LegacyRouter is broken
        """, tmp_path)
        assert detect_g1(_ctx(tmp_path)).count == 1

    def test_todo_without_camelcase_not_flagged(self, tmp_path):
        _write_src("""
            # TODO: clean this up
        """, tmp_path)
        assert detect_g1(_ctx(tmp_path)).count == 0

    def test_sample_contains_missing_name(self, tmp_path):
        _write_src("""
            # TODO: replace GhostAdapter with the new implementation
        """, tmp_path)
        result = detect_g1(_ctx(tmp_path))
        assert result.count == 1
        assert "GhostAdapter" in result.samples[0]

    def test_no_todos_returns_zero(self, tmp_path):
        _write_src("def foo(): pass", tmp_path)
        assert detect_g1(_ctx(tmp_path)).count == 0
