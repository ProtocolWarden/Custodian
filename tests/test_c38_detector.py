# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
"""Tests for C38 detector: mutable default arguments."""
from __future__ import annotations

import textwrap
from pathlib import Path

from custodian.audit_kit.code_health import detect_c38
from custodian.audit_kit.detector import AnalysisGraph, AuditContext
from custodian.audit_kit.passes.ast_forest import AstForest


def _write(tmp_path: Path, rel: str, src: str) -> None:
    p = tmp_path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(textwrap.dedent(src), encoding="utf-8")


def _ctx(tmp_path: Path, config: dict | None = None) -> AuditContext:
    (tmp_path / "src").mkdir(parents=True, exist_ok=True)
    return AuditContext(
        repo_root=tmp_path,
        src_root=tmp_path / "src",
        tests_root=tmp_path / "tests",
        config=config or {},
        plugin_modules=[],
        graph=AnalysisGraph(ast_forest=AstForest()),
    )


class TestC38:
    def test_list_default_flagged(self, tmp_path):
        _write(tmp_path, "src/foo.py", """
            def f(x=[]):
                pass
        """)
        assert detect_c38(_ctx(tmp_path)).count == 1

    def test_dict_default_flagged(self, tmp_path):
        _write(tmp_path, "src/foo.py", """
            def f(x={}):
                pass
        """)
        assert detect_c38(_ctx(tmp_path)).count == 1

    def test_set_literal_flagged(self, tmp_path):
        _write(tmp_path, "src/foo.py", """
            def f(x={1, 2, 3}):
                pass
        """)
        assert detect_c38(_ctx(tmp_path)).count == 1

    def test_set_call_flagged(self, tmp_path):
        _write(tmp_path, "src/foo.py", """
            def f(x=set()):
                pass
        """)
        assert detect_c38(_ctx(tmp_path)).count == 1

    def test_none_default_not_flagged(self, tmp_path):
        _write(tmp_path, "src/foo.py", """
            def f(x=None):
                pass
        """)
        assert detect_c38(_ctx(tmp_path)).count == 0

    def test_immutable_default_not_flagged(self, tmp_path):
        _write(tmp_path, "src/foo.py", """
            def f(x=42, y="hello", z=True):
                pass
        """)
        assert detect_c38(_ctx(tmp_path)).count == 0

    def test_kwarg_with_mutable_default_flagged(self, tmp_path):
        _write(tmp_path, "src/foo.py", """
            def f(*, extras=[]):
                pass
        """)
        assert detect_c38(_ctx(tmp_path)).count == 1

    def test_one_finding_per_function(self, tmp_path):
        _write(tmp_path, "src/foo.py", """
            def f(x=[], y={}):
                pass
        """)
        assert detect_c38(_ctx(tmp_path)).count == 1

    def test_two_functions_each_counted(self, tmp_path):
        _write(tmp_path, "src/foo.py", """
            def f(x=[]):
                pass
            def g(y={}):
                pass
        """)
        assert detect_c38(_ctx(tmp_path)).count == 2

    def test_exclude_paths_respected(self, tmp_path):
        _write(tmp_path, "src/legacy.py", """
            def f(x=[]):
                pass
        """)
        config = {"audit": {"exclude_paths": {"C38": ["src/legacy.py"]}}}
        assert detect_c38(_ctx(tmp_path, config)).count == 0

    def test_set_with_args_not_flagged(self, tmp_path):
        _write(tmp_path, "src/foo.py", """
            def f(x=set([1, 2])):
                pass
        """)
        assert detect_c38(_ctx(tmp_path)).count == 0

    def test_async_function_flagged(self, tmp_path):
        _write(tmp_path, "src/foo.py", """
            async def f(x=[]):
                pass
        """)
        assert detect_c38(_ctx(tmp_path)).count == 1
