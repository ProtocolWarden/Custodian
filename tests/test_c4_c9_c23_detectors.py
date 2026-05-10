# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
"""Tests for C4 (pass-in-except), C9 (broad exception swallow), C23 (shell=True)."""
from __future__ import annotations

import ast
import textwrap
from pathlib import Path

from custodian.audit_kit.detector import AnalysisGraph, AuditContext
from custodian.audit_kit.code_health import detect_c4, detect_c9, detect_c23
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


# ── C4: pass-in-except ────────────────────────────────────────────────────────

class TestC4:
    def test_broad_exception_pass_flagged(self, tmp_path):
        ctx = _make_context(tmp_path, {"m.py": """
            try:
                x = 1
            except Exception:
                pass
        """})
        result = detect_c4(ctx)
        assert result.count == 1

    def test_pass_in_bare_except_flagged(self, tmp_path):
        ctx = _make_context(tmp_path, {"m.py": """
            try:
                x = 1
            except:
                pass
        """})
        result = detect_c4(ctx)
        assert result.count == 1

    def test_base_exception_pass_flagged(self, tmp_path):
        ctx = _make_context(tmp_path, {"m.py": """
            try:
                x = 1
            except BaseException:
                pass
        """})
        result = detect_c4(ctx)
        assert result.count == 1

    def test_narrow_exception_pass_not_flagged(self, tmp_path):
        # specific exception type with pass is intentional suppression — not flagged
        ctx = _make_context(tmp_path, {"m.py": """
            try:
                x = 1
            except ValueError:
                pass
        """})
        result = detect_c4(ctx)
        assert result.count == 0

    def test_except_with_log_not_flagged(self, tmp_path):
        ctx = _make_context(tmp_path, {"m.py": """
            try:
                x = 1
            except Exception as e:
                logger.warning("failed: %s", e)
        """})
        result = detect_c4(ctx)
        assert result.count == 0

    def test_except_with_raise_not_flagged(self, tmp_path):
        ctx = _make_context(tmp_path, {"m.py": """
            try:
                x = 1
            except Exception:
                raise
        """})
        result = detect_c4(ctx)
        assert result.count == 0

    def test_multi_statement_except_not_flagged(self, tmp_path):
        ctx = _make_context(tmp_path, {"m.py": """
            try:
                x = 1
            except Exception:
                x = None
                pass
        """})
        result = detect_c4(ctx)
        assert result.count == 0

    def test_exclude_path_suppresses(self, tmp_path):
        ctx = _make_context(tmp_path, {"m.py": """
            try:
                x = 1
            except Exception:
                pass
        """}, config={"audit": {"exclude_paths": {"C4": ["src/m.py"]}}})
        result = detect_c4(ctx)
        assert result.count == 0


# ── C9: broad exception swallow ───────────────────────────────────────────────

class TestC9:
    def test_as_e_unused_flagged(self, tmp_path):
        ctx = _make_context(tmp_path, {"m.py": """
            try:
                x = 1
            except Exception as e:
                x = None
        """})
        result = detect_c9(ctx)
        assert result.count == 1

    def test_as_e_referenced_not_flagged(self, tmp_path):
        ctx = _make_context(tmp_path, {"m.py": """
            try:
                x = 1
            except Exception as e:
                logger.error("oops: %s", e)
        """})
        result = detect_c9(ctx)
        assert result.count == 0

    def test_no_as_not_flagged(self, tmp_path):
        # bare except Exception: without as-binding is not flagged
        ctx = _make_context(tmp_path, {"m.py": """
            try:
                x = 1
            except Exception:
                x = None
        """})
        result = detect_c9(ctx)
        assert result.count == 0

    def test_bare_except_no_as_not_flagged(self, tmp_path):
        ctx = _make_context(tmp_path, {"m.py": """
            try:
                x = 1
            except:
                x = None
        """})
        result = detect_c9(ctx)
        assert result.count == 0

    def test_except_with_raise_not_flagged(self, tmp_path):
        ctx = _make_context(tmp_path, {"m.py": """
            try:
                x = 1
            except Exception as e:
                raise
        """})
        result = detect_c9(ctx)
        assert result.count == 0

    def test_narrow_except_as_e_unused_flagged(self, tmp_path):
        # C9 applies to any except-as, not just broad ones
        ctx = _make_context(tmp_path, {"m.py": """
            try:
                x = 1
            except ValueError as e:
                x = None
        """})
        result = detect_c9(ctx)
        assert result.count == 1

    def test_exclude_path_suppresses(self, tmp_path):
        ctx = _make_context(tmp_path, {"m.py": """
            try:
                x = 1
            except Exception as e:
                x = None
        """}, config={"audit": {"exclude_paths": {"C9": ["src/m.py"]}}})
        result = detect_c9(ctx)
        assert result.count == 0


# ── C23: subprocess shell=True ────────────────────────────────────────────────

class TestC23:
    def test_shell_true_flagged(self, tmp_path):
        ctx = _make_context(tmp_path, {"m.py": """
            import subprocess
            subprocess.run("echo hi", shell=True)
        """})
        result = detect_c23(ctx)
        assert result.count == 1

    def test_popen_shell_true_flagged(self, tmp_path):
        ctx = _make_context(tmp_path, {"m.py": """
            import subprocess
            subprocess.Popen("ls", shell=True)
        """})
        result = detect_c23(ctx)
        assert result.count == 1

    def test_shell_false_not_flagged(self, tmp_path):
        ctx = _make_context(tmp_path, {"m.py": """
            import subprocess
            subprocess.run(["echo", "hi"], shell=False)
        """})
        result = detect_c23(ctx)
        assert result.count == 0

    def test_no_shell_kwarg_not_flagged(self, tmp_path):
        ctx = _make_context(tmp_path, {"m.py": """
            import subprocess
            subprocess.run(["echo", "hi"])
        """})
        result = detect_c23(ctx)
        assert result.count == 0

    def test_exclude_path_suppresses(self, tmp_path):
        ctx = _make_context(tmp_path, {"m.py": """
            import subprocess
            subprocess.run("cmd", shell=True)
        """}, config={"audit": {"exclude_paths": {"C23": ["src/m.py"]}}})
        result = detect_c23(ctx)
        assert result.count == 0
