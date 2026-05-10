# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
"""Tests for C40 detector — assert statement in production code."""
from __future__ import annotations

from pathlib import Path

from custodian.audit_kit.code_health import detect_c40
from custodian.audit_kit.detector import AnalysisGraph, AuditContext
from custodian.audit_kit.passes.ast_forest import AstForest


def _write(tmp_path: Path, rel: str, src: str) -> None:
    p = tmp_path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(src, encoding="utf-8")


def _ctx(tmp_path: Path, config: dict | None = None) -> AuditContext:
    (tmp_path / "src").mkdir(parents=True, exist_ok=True)
    (tmp_path / "tests").mkdir(parents=True, exist_ok=True)
    return AuditContext(
        repo_root=tmp_path,
        src_root=tmp_path / "src",
        tests_root=tmp_path / "tests",
        config=config or {},
        plugin_modules=[],
        graph=AnalysisGraph(ast_forest=AstForest()),
    )


class TestC40Detector:
    def test_no_asserts_clean(self, tmp_path):
        _write(tmp_path, "src/mod.py", "x = 1\n")
        assert detect_c40(_ctx(tmp_path)).count == 0

    def test_assert_in_production_flagged(self, tmp_path):
        _write(tmp_path, "src/mod.py", "def process(x):\n    assert x is not None\n    return x\n")
        result = detect_c40(_ctx(tmp_path))
        assert result.count == 1
        assert "assert statement" in result.samples[0]

    def test_assert_true_flagged(self, tmp_path):
        _write(tmp_path, "src/mod.py", "assert True\n")
        assert detect_c40(_ctx(tmp_path)).count == 1

    def test_multiple_asserts_counted(self, tmp_path):
        _write(tmp_path, "src/mod.py",
               "def check(a, b):\n    assert a is not None\n    assert b > 0\n    return a + b\n")
        assert detect_c40(_ctx(tmp_path)).count == 2

    def test_assert_in_test_file_not_flagged(self, tmp_path):
        _write(tmp_path, "src/mod.py", "x = 1\n")
        _write(tmp_path, "tests/test_mod.py", "def test_thing():\n    assert 1 == 1\n")
        assert detect_c40(_ctx(tmp_path)).count == 0

    def test_noqa_suppresses_finding(self, tmp_path):
        _write(tmp_path, "src/mod.py", "assert x is not None  # noqa: C40\n")
        assert detect_c40(_ctx(tmp_path)).count == 0

    def test_sample_includes_file_and_line(self, tmp_path):
        _write(tmp_path, "src/mod.py", "def f(x):\n    assert x\n")
        result = detect_c40(_ctx(tmp_path))
        assert result.count == 1
        assert ":2:" in result.samples[0]
        assert "mod.py" in result.samples[0]

    def test_assert_with_message_flagged(self, tmp_path):
        _write(tmp_path, "src/mod.py", "assert value > 0, 'Expected positive'\n")
        assert detect_c40(_ctx(tmp_path)).count == 1

    def test_empty_file_clean(self, tmp_path):
        _write(tmp_path, "src/mod.py", "")
        assert detect_c40(_ctx(tmp_path)).count == 0

    def test_debug_guarded_assert_not_flagged(self, tmp_path):
        _write(tmp_path, "src/mod.py", "if __debug__:\n    assert x is not None\n")
        assert detect_c40(_ctx(tmp_path)).count == 0

    def test_debug_guarded_assert_inside_function_not_flagged(self, tmp_path):
        code = (
            "def run(prompt: str) -> None:\n"
            "    if __debug__ and isinstance(prompt, str):\n"
            "        assert prompt.count('x') <= 1\n"
        )
        _write(tmp_path, "src/mod.py", code)
        assert detect_c40(_ctx(tmp_path)).count == 0

    def test_exclude_paths_respected(self, tmp_path):
        _write(tmp_path, "src/mod.py", "assert x is not None\n")
        cfg = {"audit": {"exclude_paths": {"C40": ["src/mod.py"]}}}
        assert detect_c40(_ctx(tmp_path, config=cfg)).count == 0
