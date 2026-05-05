# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Velascat
"""Tests for C7, C15, C16, C17, C18 detectors."""
from __future__ import annotations

import ast
import textwrap
from pathlib import Path

from custodian.audit_kit.detector import AnalysisGraph, AuditContext
from custodian.audit_kit.code_health import detect_c15, detect_c16, detect_c17, detect_c18
from custodian.audit_kit.passes.ast_forest import AstForest


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


# C7 (assert True) was retired 2026-05-05 — class TestC7 removed with it.


# ── C15: f-string in logger ───────────────────────────────────────────────────

class TestC15:
    def test_logger_info_fstring_flagged(self, tmp_path):
        ctx = _make_context(tmp_path, {"m.py": """
            logger.info(f"value={x}")
        """})
        result = detect_c15(ctx)
        assert result.count == 1

    def test_logger_warning_fstring_flagged(self, tmp_path):
        ctx = _make_context(tmp_path, {"m.py": """
            logger.warning(f"error: {msg}")
        """})
        result = detect_c15(ctx)
        assert result.count == 1

    def test_logger_percent_format_not_flagged(self, tmp_path):
        ctx = _make_context(tmp_path, {"m.py": """
            logger.info("value=%s", x)
        """})
        result = detect_c15(ctx)
        assert result.count == 0

    def test_logger_plain_string_not_flagged(self, tmp_path):
        ctx = _make_context(tmp_path, {"m.py": """
            logger.info("no variables here")
        """})
        result = detect_c15(ctx)
        assert result.count == 0

    def test_print_with_fstring_not_flagged(self, tmp_path):
        # C15 only flags logger calls, not print()
        ctx = _make_context(tmp_path, {"m.py": """
            print(f"value={x}")
        """})
        result = detect_c15(ctx)
        assert result.count == 0

    def test_exclude_path_suppresses(self, tmp_path):
        ctx = _make_context(tmp_path, {"m.py": """
            logger.info(f"value={x}")
        """}, config={"audit": {"exclude_paths": {"C15": ["src/m.py"]}}})
        result = detect_c15(ctx)
        assert result.count == 0


# ── C16: read_text/write_text without encoding ────────────────────────────────

class TestC16:
    def test_read_text_no_encoding_flagged(self, tmp_path):
        ctx = _make_context(tmp_path, {"m.py": """
            text = path.read_text()
        """})
        result = detect_c16(ctx)
        assert result.count == 1

    def test_write_text_no_encoding_flagged(self, tmp_path):
        ctx = _make_context(tmp_path, {"m.py": """
            path.write_text(content)
        """})
        result = detect_c16(ctx)
        assert result.count == 1

    def test_read_text_with_encoding_not_flagged(self, tmp_path):
        ctx = _make_context(tmp_path, {"m.py": """
            text = path.read_text(encoding="utf-8")
        """})
        result = detect_c16(ctx)
        assert result.count == 0

    def test_write_text_with_encoding_not_flagged(self, tmp_path):
        ctx = _make_context(tmp_path, {"m.py": """
            path.write_text(content, encoding="utf-8")
        """})
        result = detect_c16(ctx)
        assert result.count == 0

    def test_custom_write_text_two_args_not_flagged(self, tmp_path):
        # write_text(filename, content) is a custom method, not Path.write_text
        ctx = _make_context(tmp_path, {"m.py": """
            audit.write_text("file.txt", content)
        """})
        result = detect_c16(ctx)
        assert result.count == 0

    def test_exclude_path_suppresses(self, tmp_path):
        ctx = _make_context(tmp_path, {"m.py": """
            path.read_text()
        """}, config={"audit": {"exclude_paths": {"C16": ["src/m.py"]}}})
        result = detect_c16(ctx)
        assert result.count == 0


# ── C17: len(x) comparison ────────────────────────────────────────────────────

class TestC17:
    def test_len_eq_zero_flagged(self, tmp_path):
        ctx = _make_context(tmp_path, {"m.py": """
            if len(items) == 0:
                pass
        """})
        result = detect_c17(ctx)
        assert result.count == 1

    def test_len_gt_zero_flagged(self, tmp_path):
        ctx = _make_context(tmp_path, {"m.py": """
            if len(items) > 0:
                pass
        """})
        result = detect_c17(ctx)
        assert result.count == 1

    def test_len_neq_zero_flagged(self, tmp_path):
        ctx = _make_context(tmp_path, {"m.py": """
            if len(items) != 0:
                pass
        """})
        result = detect_c17(ctx)
        assert result.count == 1

    def test_truthiness_not_flagged(self, tmp_path):
        ctx = _make_context(tmp_path, {"m.py": """
            if items:
                pass
        """})
        result = detect_c17(ctx)
        assert result.count == 0

    def test_len_eq_nonzero_not_flagged(self, tmp_path):
        ctx = _make_context(tmp_path, {"m.py": """
            if len(items) == 5:
                pass
        """})
        result = detect_c17(ctx)
        assert result.count == 0

    def test_exclude_path_suppresses(self, tmp_path):
        ctx = _make_context(tmp_path, {"m.py": """
            if len(x) == 0:
                pass
        """}, config={"audit": {"exclude_paths": {"C17": ["src/m.py"]}}})
        result = detect_c17(ctx)
        assert result.count == 0


# ── C18: useless f-string ─────────────────────────────────────────────────────

class TestC18:
    def test_fstring_no_interp_flagged(self, tmp_path):
        ctx = _make_context(tmp_path, {"m.py": """
            x = f"hello world"
        """})
        result = detect_c18(ctx)
        assert result.count == 1

    def test_fstring_with_interp_not_flagged(self, tmp_path):
        ctx = _make_context(tmp_path, {"m.py": """
            x = f"hello {name}"
        """})
        result = detect_c18(ctx)
        assert result.count == 0

    def test_fstring_with_format_spec_not_flagged(self, tmp_path):
        # f"{x:>4}" — valid f-string with format spec
        ctx = _make_context(tmp_path, {"m.py": """
            x = f"{n:>4}"
        """})
        result = detect_c18(ctx)
        assert result.count == 0

    def test_fstring_nested_format_spec_not_flagged(self, tmp_path):
        # f"{'ID':<6}" — format spec has nested JoinedStr, must not double-count
        ctx = _make_context(tmp_path, {"m.py": """
            x = f"{'ID':<6} {'SEV':<6} description"
        """})
        result = detect_c18(ctx)
        assert result.count == 0

    def test_plain_string_not_flagged(self, tmp_path):
        ctx = _make_context(tmp_path, {"m.py": """
            x = "hello world"
        """})
        result = detect_c18(ctx)
        assert result.count == 0

    def test_exclude_path_suppresses(self, tmp_path):
        ctx = _make_context(tmp_path, {"m.py": """
            x = f"no interp"
        """}, config={"audit": {"exclude_paths": {"C18": ["src/m.py"]}}})
        result = detect_c18(ctx)
        assert result.count == 0
