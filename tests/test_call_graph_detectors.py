# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
"""Tests for call-graph pass, D1 (dead functions), and F1 (dead dataclass fields)."""
from __future__ import annotations

import textwrap
from pathlib import Path
from unittest.mock import patch

from custodian.audit_kit.detector import AnalysisGraph, AuditContext
from custodian.audit_kit.detectors.dead_code import detect_d1, detect_f1
from custodian.audit_kit.passes.call_graph import _collect_usages_only, build_call_graph


# ── helpers ───────────────────────────────────────────────────────────────────

def _write_src(src: str, tmp_path: Path, name: str = "module.py") -> Path:
    src_root = tmp_path / "src"
    src_root.mkdir(parents=True, exist_ok=True)
    path = src_root / name
    path.write_text(textwrap.dedent(src), encoding="utf-8")
    return path


def _ctx_with_cg(tmp_path: Path) -> AuditContext:
    src_root = tmp_path / "src"
    src_root.mkdir(parents=True, exist_ok=True)
    cg = build_call_graph(src_root)
    return AuditContext(
        repo_root=tmp_path,
        src_root=src_root,
        tests_root=tmp_path / "tests",
        config={},
        plugin_modules=[],
        graph=AnalysisGraph(call_graph=cg),
    )


# ── CallGraph pass tests ───────────────────────────────────────────────────────

class TestCallGraph:
    def test_empty_src_root(self, tmp_path):
        cg = build_call_graph(tmp_path / "src")
        assert cg.module_functions == set()
        assert cg.called_names == set()

    def test_collects_module_function(self, tmp_path):
        _write_src("def foo(): pass", tmp_path)
        cg = build_call_graph(tmp_path / "src")
        assert "foo" in cg.module_functions

    def test_does_not_collect_method_as_module_function(self, tmp_path):
        _write_src("""
            class Foo:
                def bar(self): pass
        """, tmp_path)
        cg = build_call_graph(tmp_path / "src")
        assert "bar" not in cg.module_functions
        assert "bar" in cg.all_defined

    def test_collects_call_name(self, tmp_path):
        _write_src("foo()", tmp_path)
        cg = build_call_graph(tmp_path / "src")
        assert "foo" in cg.called_names

    def test_collects_attribute_call(self, tmp_path):
        _write_src("obj.run()", tmp_path)
        cg = build_call_graph(tmp_path / "src")
        assert "run" in cg.called_attrs

    def test_collects_attribute_access(self, tmp_path):
        _write_src("x = obj.value", tmp_path)
        cg = build_call_graph(tmp_path / "src")
        assert "value" in cg.accessed_attrs

    def test_collects_all_exports(self, tmp_path):
        _write_src('__all__ = ["helper"]\ndef helper(): pass', tmp_path)
        cg = build_call_graph(tmp_path / "src")
        assert "helper" in cg.defined_in_all

    def test_collects_decorator_name(self, tmp_path):
        _write_src("""
            def my_decorator(f): return f
            @my_decorator
            def foo(): pass
        """, tmp_path)
        cg = build_call_graph(tmp_path / "src")
        assert "my_decorator" in cg.decorated_names

    def test_collect_usages_only_walks_tree_once(self):
        tree = __import__("ast").parse(
            textwrap.dedent(
                """
                class Child(Base):
                    pass

                Foo.model_validate(payload)
                obj.run()
                value = obj.field
                """
            )
        )
        walk_calls = 0
        import ast

        real_walk = ast.walk

        def _counting_walk(node):
            nonlocal walk_calls
            walk_calls += 1
            return real_walk(node)

        with patch("custodian.audit_kit.passes.call_graph.ast.walk", side_effect=_counting_walk):
            cg = build_call_graph(Path("/tmp/does-not-matter"))
            _collect_usages_only(tree, cg)

        assert walk_calls == 1
        assert "Base" in cg.constructed_names
        assert "run" in cg.called_attrs
        assert "field" in cg.accessed_attrs
        assert "Foo" in cg.model_validate_classes


# ── D1 tests ──────────────────────────────────────────────────────────────────

class TestD1:
    def test_no_call_graph_returns_zero(self, tmp_path):
        ctx = AuditContext(
            repo_root=tmp_path, src_root=tmp_path / "src",
            tests_root=tmp_path / "tests", config={}, plugin_modules=[],
            graph=AnalysisGraph(call_graph=None),
        )
        assert detect_d1(ctx).count == 0

    def test_called_function_not_flagged(self, tmp_path):
        _write_src("""
            def helper(): pass
            helper()
        """, tmp_path)
        assert detect_d1(_ctx_with_cg(tmp_path)).count == 0

    def test_uncalled_public_function_flagged(self, tmp_path):
        _write_src("def orphan(): pass", tmp_path)
        assert detect_d1(_ctx_with_cg(tmp_path)).count == 1

    def test_private_function_not_flagged(self, tmp_path):
        _write_src("def _helper(): pass", tmp_path)
        assert detect_d1(_ctx_with_cg(tmp_path)).count == 0

    def test_test_prefixed_function_not_flagged(self, tmp_path):
        _write_src("def test_something(): pass", tmp_path)
        assert detect_d1(_ctx_with_cg(tmp_path)).count == 0

    def test_main_not_flagged(self, tmp_path):
        _write_src("def main(): pass", tmp_path)
        assert detect_d1(_ctx_with_cg(tmp_path)).count == 0

    def test_exported_via_all_not_flagged(self, tmp_path):
        _write_src('__all__ = ["orphan"]\ndef orphan(): pass', tmp_path)
        assert detect_d1(_ctx_with_cg(tmp_path)).count == 0

    def test_decorator_function_not_flagged(self, tmp_path):
        # my_dec is used as a decorator — it should not be flagged even though
        # it is never called directly with my_dec(...).
        _write_src("""
            def my_dec(f): return f
            @my_dec
            def foo(): pass
            foo()
        """, tmp_path)
        result = detect_d1(_ctx_with_cg(tmp_path))
        names = [s.split("(")[0] for s in result.samples]
        assert "my_dec" not in names

    def test_called_as_attribute_not_flagged(self, tmp_path):
        # bar is called via obj.bar() — shows up in called_attrs
        _write_src("""
            def bar(): pass
            class X:
                def run(self):
                    self.bar()
        """, tmp_path)
        assert detect_d1(_ctx_with_cg(tmp_path)).count == 0

    def test_sample_contains_function_name(self, tmp_path):
        _write_src("def lonely(): pass", tmp_path)
        result = detect_d1(_ctx_with_cg(tmp_path))
        assert result.count == 1
        assert "lonely" in result.samples[0]


# ── F1 tests ──────────────────────────────────────────────────────────────────

class TestF1:
    def test_no_call_graph_returns_zero(self, tmp_path):
        ctx = AuditContext(
            repo_root=tmp_path, src_root=tmp_path / "src",
            tests_root=tmp_path / "tests", config={}, plugin_modules=[],
            graph=AnalysisGraph(call_graph=None),
        )
        assert detect_f1(ctx).count == 0

    def test_accessed_field_not_flagged(self, tmp_path):
        _write_src("""
            from dataclasses import dataclass
            @dataclass
            class Config:
                timeout: int = 30

            c = Config()
            print(c.timeout)
        """, tmp_path)
        assert detect_f1(_ctx_with_cg(tmp_path)).count == 0

    def test_unaccessed_field_flagged(self, tmp_path):
        _write_src("""
            from dataclasses import dataclass
            @dataclass
            class Config:
                timeout: int = 30
        """, tmp_path)
        assert detect_f1(_ctx_with_cg(tmp_path)).count == 1

    def test_non_dataclass_field_not_flagged(self, tmp_path):
        _write_src("""
            class Config:
                timeout: int = 30
        """, tmp_path)
        assert detect_f1(_ctx_with_cg(tmp_path)).count == 0

    def test_private_field_not_flagged(self, tmp_path):
        _write_src("""
            from dataclasses import dataclass
            @dataclass
            class Config:
                _internal: int = 0
        """, tmp_path)
        assert detect_f1(_ctx_with_cg(tmp_path)).count == 0

    def test_sample_contains_field_name(self, tmp_path):
        _write_src("""
            from dataclasses import dataclass
            @dataclass
            class Config:
                orphan_field: str = ""
        """, tmp_path)
        result = detect_f1(_ctx_with_cg(tmp_path))
        assert result.count == 1
        assert "orphan_field" in result.samples[0]
