# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
"""Tests for C36 (built-in open() in text mode without encoding=)."""
from __future__ import annotations

from pathlib import Path

from custodian.audit_kit.detector import AuditContext
from custodian.audit_kit.code_health import detect_c36


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


class TestC36:
    def test_bare_open_flagged(self, tmp_path):
        ctx = _ctx(tmp_path, {"m.py": "with open('f.txt') as f: pass\n"})
        assert detect_c36(ctx).count == 1

    def test_text_mode_open_flagged(self, tmp_path):
        ctx = _ctx(tmp_path, {"m.py": "with open('f.txt', 'w') as f: pass\n"})
        assert detect_c36(ctx).count == 1

    def test_binary_mode_not_flagged(self, tmp_path):
        ctx = _ctx(tmp_path, {"m.py": "with open('f.bin', 'rb') as f: pass\n"})
        assert detect_c36(ctx).count == 0

    def test_binary_write_not_flagged(self, tmp_path):
        ctx = _ctx(tmp_path, {"m.py": "with open('f.bin', 'wb') as f: pass\n"})
        assert detect_c36(ctx).count == 0

    def test_encoding_kwarg_not_flagged(self, tmp_path):
        ctx = _ctx(tmp_path, {"m.py": "with open('f.txt', encoding='utf-8') as f: pass\n"})
        assert detect_c36(ctx).count == 0

    def test_encoding_with_mode_not_flagged(self, tmp_path):
        ctx = _ctx(tmp_path, {"m.py": "with open('f.txt', 'r', encoding='utf-8') as f: pass\n"})
        assert detect_c36(ctx).count == 0

    def test_attribute_open_not_flagged(self, tmp_path):
        # wave.open(), Image.open(), etc. are not the built-in open()
        ctx = _ctx(tmp_path, {"m.py": "import wave\nwith wave.open('f.wav', 'rb') as f: pass\n"})
        assert detect_c36(ctx).count == 0

    def test_mode_kwarg_binary_not_flagged(self, tmp_path):
        ctx = _ctx(tmp_path, {"m.py": "open('f', mode='rb')\n"})
        assert detect_c36(ctx).count == 0

    def test_exclude_paths(self, tmp_path):
        ctx = _ctx(tmp_path, {"legacy/m.py": "open('f.txt')\n"}, config={
            "audit": {"exclude_paths": {"C36": ["src/legacy/**"]}}
        })
        assert detect_c36(ctx).count == 0
