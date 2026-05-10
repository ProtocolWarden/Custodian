# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
"""Tests for T5 detector: single-case pytest.mark.parametrize."""
from __future__ import annotations

import textwrap
from pathlib import Path

from custodian.audit_kit.detector import AnalysisGraph, AuditContext
from custodian.audit_kit.detectors.test_shape import detect_t5
from custodian.audit_kit.passes.ast_forest import AstForest


def _write(tmp_path: Path, rel: str, src: str) -> None:
    p = tmp_path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(textwrap.dedent(src), encoding="utf-8")


def _ctx(tmp_path: Path) -> AuditContext:
    (tmp_path / "src").mkdir(parents=True, exist_ok=True)
    return AuditContext(
        repo_root=tmp_path,
        src_root=tmp_path / "src",
        tests_root=tmp_path / "tests",
        config={},
        plugin_modules=[],
        graph=AnalysisGraph(ast_forest=AstForest()),
    )


class TestT5:
    def test_no_tests_root_returns_zero(self, tmp_path):
        ctx = AuditContext(
            repo_root=tmp_path,
            src_root=tmp_path / "src",
            tests_root=tmp_path / "nonexistent",
            config={},
            plugin_modules=[],
            graph=AnalysisGraph(ast_forest=AstForest()),
        )
        assert detect_t5(ctx).count == 0

    def test_no_parametrize_is_clean(self, tmp_path):
        _write(tmp_path, "tests/test_x.py", """\
            def test_something():
                assert 1 + 1 == 2
        """)
        assert detect_t5(_ctx(tmp_path)).count == 0

    def test_multi_case_parametrize_not_flagged(self, tmp_path):
        _write(tmp_path, "tests/test_x.py", """\
            import pytest

            @pytest.mark.parametrize("x", [1, 2, 3])
            def test_multi(x):
                assert x > 0
        """)
        assert detect_t5(_ctx(tmp_path)).count == 0

    def test_single_case_parametrize_flagged(self, tmp_path):
        _write(tmp_path, "tests/test_x.py", """\
            import pytest

            @pytest.mark.parametrize("key", ["only_one"])
            def test_single(key):
                assert key == "only_one"
        """)
        result = detect_t5(_ctx(tmp_path))
        assert result.count == 1
        assert "test_single" in result.samples[0]
        assert "1 case" in result.samples[0]

    def test_single_tuple_case_flagged(self, tmp_path):
        _write(tmp_path, "tests/test_x.py", """\
            import pytest

            @pytest.mark.parametrize("x,y", [(1, 2)])
            def test_pair(x, y):
                assert x < y
        """)
        result = detect_t5(_ctx(tmp_path))
        assert result.count == 1

    def test_two_cases_not_flagged(self, tmp_path):
        _write(tmp_path, "tests/test_x.py", """\
            import pytest

            @pytest.mark.parametrize("x,y", [(1, 2), (3, 4)])
            def test_pairs(x, y):
                assert x < y
        """)
        assert detect_t5(_ctx(tmp_path)).count == 0

    def test_variable_arg_list_not_flagged(self, tmp_path):
        _write(tmp_path, "tests/test_x.py", """\
            import pytest

            CASES = ["a"]

            @pytest.mark.parametrize("x", CASES)
            def test_var(x):
                assert x
        """)
        assert detect_t5(_ctx(tmp_path)).count == 0

    def test_empty_list_not_flagged(self, tmp_path):
        _write(tmp_path, "tests/test_x.py", """\
            import pytest

            @pytest.mark.parametrize("x", [])
            def test_empty(x):
                assert x
        """)
        assert detect_t5(_ctx(tmp_path)).count == 0

    def test_multiple_tests_only_one_single_case(self, tmp_path):
        _write(tmp_path, "tests/test_x.py", """\
            import pytest

            @pytest.mark.parametrize("x", ["only"])
            def test_bad(x):
                assert x

            @pytest.mark.parametrize("x", [1, 2])
            def test_good(x):
                assert x
        """)
        result = detect_t5(_ctx(tmp_path))
        assert result.count == 1
        assert "test_bad" in result.samples[0]

    def test_sample_includes_file_and_line(self, tmp_path):
        _write(tmp_path, "tests/test_x.py", """\
            import pytest

            @pytest.mark.parametrize("v", ["val"])
            def test_it(v):
                assert v
        """)
        result = detect_t5(_ctx(tmp_path))
        assert result.count == 1
        assert "tests/test_x.py" in result.samples[0]
