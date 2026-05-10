# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
"""Tests for T1 — public src symbols with no test references."""
from __future__ import annotations

import ast
import textwrap
from pathlib import Path

from custodian.audit_kit.detector import AnalysisGraph, AuditContext
from custodian.audit_kit.detectors.test_shape import detect_t1
from custodian.audit_kit.passes.ast_forest import AstForest
from custodian.audit_kit.passes.tests_forest import build_tests_forest


def _write_src(src: str, tmp_path: Path, name: str = "module.py") -> None:
    src_root = tmp_path / "src"
    src_root.mkdir(parents=True, exist_ok=True)
    (src_root / name).write_text(textwrap.dedent(src), encoding="utf-8")


def _write_test(src: str, tmp_path: Path, name: str = "test_mod.py") -> None:
    tests_root = tmp_path / "tests"
    tests_root.mkdir(parents=True, exist_ok=True)
    (tests_root / name).write_text(textwrap.dedent(src), encoding="utf-8")


def _ctx(tmp_path: Path) -> AuditContext:
    src_root = tmp_path / "src"
    tests_root = tmp_path / "tests"
    src_root.mkdir(parents=True, exist_ok=True)

    # Build ast_forest from src
    forest = AstForest()
    for path in sorted(src_root.rglob("*.py")):
        text = path.read_text(encoding="utf-8")
        tree = ast.parse(text)
        forest.trees[path] = tree
        forest.sources[path] = text

    tf = build_tests_forest(tests_root)

    return AuditContext(
        repo_root=tmp_path,
        src_root=src_root,
        tests_root=tests_root,
        config={},
        plugin_modules=[],
        graph=AnalysisGraph(ast_forest=forest, tests_forest=tf),
    )


class TestT1:
    def test_no_forest_returns_zero(self, tmp_path):
        ctx = AuditContext(
            repo_root=tmp_path, src_root=tmp_path / "src",
            tests_root=tmp_path / "tests", config={}, plugin_modules=[],
            graph=AnalysisGraph(ast_forest=None, tests_forest=None),
        )
        assert detect_t1(ctx).count == 0

    def test_referenced_function_not_flagged(self, tmp_path):
        _write_src("def helper(): pass", tmp_path)
        _write_test("from mod import helper\ndef test_it():\n    helper()", tmp_path)
        assert detect_t1(_ctx(tmp_path)).count == 0

    def test_unreferenced_public_function_flagged(self, tmp_path):
        _write_src("def orphan(): pass", tmp_path)
        _write_test("def test_other(): assert True", tmp_path)
        assert detect_t1(_ctx(tmp_path)).count == 1

    def test_private_function_not_flagged(self, tmp_path):
        _write_src("def _internal(): pass", tmp_path)
        _write_test("def test_other(): assert True", tmp_path)
        assert detect_t1(_ctx(tmp_path)).count == 0

    def test_class_referenced_by_name_not_flagged(self, tmp_path):
        _write_src("class MyService: pass", tmp_path)
        _write_test("from mod import MyService\ndef test_it():\n    s = MyService()", tmp_path)
        assert detect_t1(_ctx(tmp_path)).count == 0

    def test_no_tests_root_all_flagged(self, tmp_path):
        _write_src("def foo(): pass\ndef bar(): pass", tmp_path)
        # no tests written → empty tests_forest
        assert detect_t1(_ctx(tmp_path)).count == 2

    def test_sample_contains_symbol_name(self, tmp_path):
        _write_src("def lonely_func(): pass", tmp_path)
        result = detect_t1(_ctx(tmp_path))
        assert result.count == 1
        assert "lonely_func" in result.samples[0]
