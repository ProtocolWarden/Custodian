# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
"""Tests for C34 (commented-out function/class/decorator definitions)."""
from __future__ import annotations

from pathlib import Path

from custodian.audit_kit.detector import AuditContext
from custodian.audit_kit.code_health import detect_c34


def _ctx(tmp_path: Path, src_files: dict[str, str], config: dict | None = None) -> AuditContext:
    src_root = tmp_path / "src"
    for rel, content in src_files.items():
        p = src_root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
    return AuditContext(
        repo_root=tmp_path,
        src_root=src_root,
        tests_root=tmp_path / "tests",
        config=config or {},
        plugin_modules=[],
    )


class TestC34:
    def test_commented_def_flagged(self, tmp_path):
        ctx = _ctx(tmp_path, {"m.py": "# def old_function():\n#     pass\n"})
        assert detect_c34(ctx).count == 1

    def test_commented_async_def_flagged(self, tmp_path):
        ctx = _ctx(tmp_path, {"m.py": "# async def fetch_data():\n#     return []\n"})
        assert detect_c34(ctx).count == 1

    def test_commented_class_flagged(self, tmp_path):
        ctx = _ctx(tmp_path, {"m.py": "# class OldModel:\n#     pass\n"})
        assert detect_c34(ctx).count == 1

    def test_commented_decorator_flagged(self, tmp_path):
        ctx = _ctx(tmp_path, {"m.py": "# @deprecated\n# def old():\n#     pass\n"})
        result = detect_c34(ctx)
        assert result.count == 2  # decorator + def

    def test_regular_comment_not_flagged(self, tmp_path):
        ctx = _ctx(tmp_path, {"m.py": "# This uses a class-like approach\n# See BaseHandler for context\nx = 1\n"})
        assert detect_c34(ctx).count == 0

    def test_url_comment_not_flagged(self, tmp_path):
        ctx = _ctx(tmp_path, {"m.py": "# https://docs.python.org/3/reference/\nx = 1\n"})
        assert detect_c34(ctx).count == 0

    def test_multiple_files(self, tmp_path):
        ctx = _ctx(tmp_path, {
            "a.py": "# def removed(): pass\n",
            "b.py": "# class OldClass: pass\n",
            "c.py": "# just a comment\n",
        })
        result = detect_c34(ctx)
        assert result.count == 2

    def test_exclude_paths(self, tmp_path):
        ctx = _ctx(tmp_path, {"legacy/m.py": "# def old(): pass\n"}, config={
            "audit": {"exclude_paths": {"C34": ["src/legacy/**"]}}
        })
        assert detect_c34(ctx).count == 0

    def test_live_def_not_flagged(self, tmp_path):
        ctx = _ctx(tmp_path, {"m.py": "def real_function():\n    return 1\n"})
        assert detect_c34(ctx).count == 0
