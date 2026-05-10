# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
"""Tests for C35 (bare # type: ignore without error-code brackets)."""
from __future__ import annotations

from pathlib import Path

from custodian.audit_kit.detector import AuditContext
from custodian.audit_kit.code_health import detect_c35


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


class TestC35:
    def test_bare_type_ignore_flagged(self, tmp_path):
        ctx = _ctx(tmp_path, {"m.py": 'x = something()  # type: ignore\n'})
        assert detect_c35(ctx).count == 1

    def test_bracketed_type_ignore_not_flagged(self, tmp_path):
        ctx = _ctx(tmp_path, {"m.py": 'x = something()  # type: ignore[attr-defined]\n'})
        assert detect_c35(ctx).count == 0

    def test_comment_only_line_not_flagged(self, tmp_path):
        # A comment-only line discussing type: ignore is not an active suppression
        ctx = _ctx(tmp_path, {"m.py": '# Use type: ignore for suppression\nx = 1\n'})
        assert detect_c35(ctx).count == 0

    def test_bare_import_ignore_flagged(self, tmp_path):
        ctx = _ctx(tmp_path, {"m.py": 'import optional  # type: ignore\n'})
        assert detect_c35(ctx).count == 1

    def test_type_ignore_in_string_not_flagged(self, tmp_path):
        # type: ignore in a string literal is not a real suppression
        ctx = _ctx(tmp_path, {"m.py": 'msg = "use # type: ignore[attr-defined]"\nx = 1\n'})
        assert detect_c35(ctx).count == 0

    def test_type_ignore_in_docstring_not_flagged(self, tmp_path):
        ctx = _ctx(tmp_path, {"m.py": '"""Example: x = foo()  # type: ignore for suppression."""\nx = 1\n'})
        assert detect_c35(ctx).count == 0

    def test_multiple_files(self, tmp_path):
        ctx = _ctx(tmp_path, {
            "a.py": 'x = f()  # type: ignore\n',
            "b.py": 'y = g()  # type: ignore[return-value]\n',
            "c.py": 'z = h()  # type: ignore\n',
        })
        assert detect_c35(ctx).count == 2

    def test_exclude_paths(self, tmp_path):
        ctx = _ctx(tmp_path, {"legacy/m.py": 'x = f()  # type: ignore\n'}, config={
            "audit": {"exclude_paths": {"C35": ["src/legacy/**"]}}
        })
        assert detect_c35(ctx).count == 0
