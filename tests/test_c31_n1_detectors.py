# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
"""Tests for C31 (weak hash), N1 (exception naming), and P1 refinements."""
from __future__ import annotations

import ast
import textwrap
from pathlib import Path

from custodian.audit_kit.detector import AnalysisGraph, AuditContext
from custodian.audit_kit.code_health import detect_c31
from custodian.audit_kit.detectors.naming import detect_n1
from custodian.audit_kit.detectors.stubs import detect_p1
from custodian.audit_kit.passes.ast_forest import AstForest


# ── helpers ──────────────────────────────────────────────────────────────────

def _make_context(tmp_path: Path, src_files: dict[str, str], config: dict | None = None) -> AuditContext:
    src_root = tmp_path / "src"
    for rel, content in src_files.items():
        p = src_root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(textwrap.dedent(content), encoding="utf-8")
    forest = AstForest()
    for rel in src_files:
        p = src_root / rel
        text = p.read_text(encoding="utf-8")
        try:
            forest.trees[p] = ast.parse(text)
            forest.sources[p] = text
        except SyntaxError:
            pass
    graph = AnalysisGraph(ast_forest=forest)
    return AuditContext(
        repo_root=tmp_path,
        src_root=src_root,
        tests_root=tmp_path / "tests",
        config=config or {},
        plugin_modules=[],
        graph=graph,
    )


# ── C31 ──────────────────────────────────────────────────────────────────────

class TestC31:
    def test_sha1_without_flag_flagged(self, tmp_path):
        ctx = _make_context(tmp_path, {"m.py": """
            import hashlib
            h = hashlib.sha1(data)
        """})
        result = detect_c31(ctx)
        assert result.count == 1
        assert ".sha1()" in result.samples[0]

    def test_md5_without_flag_flagged(self, tmp_path):
        ctx = _make_context(tmp_path, {"m.py": """
            import hashlib
            h = hashlib.md5(data)
        """})
        result = detect_c31(ctx)
        assert result.count == 1

    def test_sha1_with_usedforsecurity_false_ok(self, tmp_path):
        ctx = _make_context(tmp_path, {"m.py": """
            import hashlib
            h = hashlib.sha1(data, usedforsecurity=False)
        """})
        result = detect_c31(ctx)
        assert result.count == 0

    def test_no_hashlib_import_not_flagged(self, tmp_path):
        ctx = _make_context(tmp_path, {"m.py": """
            h = obj.sha1(data)  # unrelated method
        """})
        result = detect_c31(ctx)
        assert result.count == 0

    def test_aliased_hashlib_import_flagged(self, tmp_path):
        ctx = _make_context(tmp_path, {"m.py": """
            import hashlib as _hashlib
            h = _hashlib.sha1(data)
        """})
        result = detect_c31(ctx)
        assert result.count == 1

    def test_sha256_not_flagged(self, tmp_path):
        ctx = _make_context(tmp_path, {"m.py": """
            import hashlib
            h = hashlib.sha256(data)
        """})
        result = detect_c31(ctx)
        assert result.count == 0


# ── N1 ───────────────────────────────────────────────────────────────────────

class TestN1:
    def test_exception_without_error_suffix_flagged(self, tmp_path):
        ctx = _make_context(tmp_path, {"m.py": """
            class MyTimeout(Exception):
                pass
        """})
        result = detect_n1(ctx)
        assert result.count == 1
        assert "MyTimeout" in result.samples[0]

    def test_exception_with_error_suffix_ok(self, tmp_path):
        ctx = _make_context(tmp_path, {"m.py": """
            class MyTimeoutError(Exception):
                pass
        """})
        result = detect_n1(ctx)
        assert result.count == 0

    def test_exception_with_exception_suffix_ok(self, tmp_path):
        ctx = _make_context(tmp_path, {"m.py": """
            class MyTimeoutException(Exception):
                pass
        """})
        result = detect_n1(ctx)
        assert result.count == 0

    def test_exception_with_warning_suffix_ok(self, tmp_path):
        ctx = _make_context(tmp_path, {"m.py": """
            class MyDeprecationWarning(Warning):
                pass
        """})
        result = detect_n1(ctx)
        assert result.count == 0

    def test_control_flow_stop_ok(self, tmp_path):
        ctx = _make_context(tmp_path, {"m.py": """
            class PipelineStop(Exception):
                pass
        """})
        result = detect_n1(ctx)
        assert result.count == 0

    def test_control_flow_abort_ok(self, tmp_path):
        ctx = _make_context(tmp_path, {"m.py": """
            class LoopAbort(Exception):
                pass
        """})
        result = detect_n1(ctx)
        assert result.count == 0

    def test_non_exception_class_not_flagged(self, tmp_path):
        ctx = _make_context(tmp_path, {"m.py": """
            class FooService:
                pass
        """})
        result = detect_n1(ctx)
        assert result.count == 0


# ── P1 refinements ───────────────────────────────────────────────────────────

class TestP1Refinements:
    def _p1(self, tmp_path, src: str) -> int:
        ctx = _make_context(tmp_path, {"m.py": src})
        return detect_p1(ctx).count

    def test_void_annotated_return_not_flagged(self, tmp_path):
        assert self._p1(tmp_path, """
            class Obs:
                def flush(self) -> None:
                    return
        """) == 0

    def test_sink_kwargs_not_flagged(self, tmp_path):
        assert self._p1(tmp_path, """
            class NullEmitter:
                def emit(self, **_):
                    return None
        """) == 0

    def test_null_class_not_flagged(self, tmp_path):
        assert self._p1(tmp_path, """
            class NullBackend:
                def get_items(self, x):
                    return []
        """) == 0

    def test_regular_hollow_return_still_flagged(self, tmp_path):
        assert self._p1(tmp_path, """
            def get_handlers():
                return []
        """) == 1

    def test_sink_vararg_not_flagged(self, tmp_path):
        assert self._p1(tmp_path, """
            def hook(*_args, **_kwargs):
                return []
        """) == 0
