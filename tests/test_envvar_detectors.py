# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
"""Tests for E-class env-var drift detectors (E1)."""

from __future__ import annotations

from pathlib import Path

from custodian.audit_kit.detector import AuditContext
from custodian.audit_kit.detectors.envvar import build_envvar_detectors


def _ctx(tmp_path: Path, config: dict | None = None) -> AuditContext:
    src = tmp_path / "src"
    src.mkdir(exist_ok=True)
    return AuditContext(
        repo_root=tmp_path,
        src_root=src,
        tests_root=tmp_path / "tests",
        config=config or {"repo_key": "TestRepo", "src_root": "src", "tests_root": "tests"},
        plugin_modules=[],
    )


def _e1(tmp_path, config=None):
    return build_envvar_detectors()[0]


def _write_src(tmp_path: Path, code: str, name: str = "app.py") -> None:
    src = tmp_path / "src"
    src.mkdir(exist_ok=True)
    (src / name).write_text(code, encoding="utf-8")


def _write_example(tmp_path: Path, content: str) -> None:
    (tmp_path / ".env.example").write_text(content, encoding="utf-8")


# ── E1: env-var drift ─────────────────────────────────────────────────────────

class TestE1EnvVarDrift:
    def test_no_env_example_skips(self, tmp_path):
        _write_src(tmp_path, 'import os\nval = os.environ.get("MY_KEY")\n')
        result = _e1(tmp_path).detect(_ctx(tmp_path))
        assert result.count == 0

    def test_key_documented_passes(self, tmp_path):
        _write_src(tmp_path, 'import os\nval = os.environ.get("MY_KEY")\n')
        _write_example(tmp_path, "MY_KEY=\n")
        result = _e1(tmp_path).detect(_ctx(tmp_path))
        assert result.count == 0

    def test_key_in_commented_example_passes(self, tmp_path):
        _write_src(tmp_path, 'import os\nval = os.environ.get("MY_KEY")\n')
        _write_example(tmp_path, "# MY_KEY=some_default\n")
        result = _e1(tmp_path).detect(_ctx(tmp_path))
        assert result.count == 0

    def test_undocumented_key_flagged(self, tmp_path):
        _write_src(tmp_path, 'import os\nval = os.environ.get("MY_KEY")\n')
        _write_example(tmp_path, "OTHER_KEY=\n")
        result = _e1(tmp_path).detect(_ctx(tmp_path))
        assert result.count == 1
        assert "MY_KEY" in result.samples[0]

    def test_os_getenv_detected(self, tmp_path):
        _write_src(tmp_path, 'import os\nval = os.getenv("MY_KEY")\n')
        _write_example(tmp_path, "OTHER_KEY=\n")
        result = _e1(tmp_path).detect(_ctx(tmp_path))
        assert result.count == 1
        assert "MY_KEY" in result.samples[0]

    def test_os_environ_subscript_detected(self, tmp_path):
        _write_src(tmp_path, 'import os\nval = os.environ["MY_KEY"]\n')
        _write_example(tmp_path, "OTHER_KEY=\n")
        result = _e1(tmp_path).detect(_ctx(tmp_path))
        assert result.count == 1
        assert "MY_KEY" in result.samples[0]

    def test_system_var_exempt(self, tmp_path):
        _write_src(tmp_path, 'import os\nuser = os.environ.get("USER")\npath = os.getenv("HOME")\n')
        _write_example(tmp_path, "APP_KEY=\n")
        result = _e1(tmp_path).detect(_ctx(tmp_path))
        assert result.count == 0

    def test_multiple_undocumented_flagged(self, tmp_path):
        _write_src(tmp_path, (
            'import os\n'
            'a = os.environ.get("KEY_A")\n'
            'b = os.getenv("KEY_B")\n'
        ))
        _write_example(tmp_path, "KEY_A=\n")
        result = _e1(tmp_path).detect(_ctx(tmp_path))
        assert result.count == 1
        assert "KEY_B" in result.samples[0]

    def test_config_skip_keys_exempt(self, tmp_path):
        _write_src(tmp_path, 'import os\nval = os.environ.get("INTERNAL_KEY")\n')
        _write_example(tmp_path, "OTHER_KEY=\n")
        config = {
            "repo_key": "TestRepo", "src_root": "src", "tests_root": "tests",
            "envvar": {"skip_keys": ["INTERNAL_KEY"]},
        }
        result = _e1(tmp_path).detect(_ctx(tmp_path, config=config))
        assert result.count == 0

    def test_no_src_files_passes(self, tmp_path):
        _write_example(tmp_path, "KEY=\n")
        result = _e1(tmp_path).detect(_ctx(tmp_path))
        assert result.count == 0

    def test_detector_id(self, tmp_path):
        assert _e1(tmp_path).id == "E1"
